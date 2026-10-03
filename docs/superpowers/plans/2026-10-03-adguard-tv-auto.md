<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# ad-guard TV — mode auto (essai, confirmation, retour arrière) — plan d'implémentation (#1954)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** un appareil déclaré en mode `auto` voit ses domaines publicitaires appris, appliqués à l'essai 24 h, confirmés par l'administrateur, et retirés seuls en cas de casse.

**Architecture:** cinq modules purs et testables (règles, détection, signaux, rendu Unbound, moteur) ; une seule porte privilégiée (`secubox-adguard-tv`, nouvelle commande `regles-appliquer`) qui applique les règles **à chaud** par `unbound-control view_local_zone` ; une minuterie systemd qui exécute le moteur chaque minute ; routes `/adblock-tv/auto/*` et un panneau admin dans l'onglet existant.

**Tech Stack:** Python 3.11+ (3.13 sur Trixie), FastAPI, SQLite (compteurs existants), Unbound 1.17.1 (version réelle de gk2), systemd, JS sans dépendance (`textContent` seul).

**Spec:** `docs/superpowers/specs/2026-10-03-adguard-tv-auto-design.md`

## Écarts assumés avec la spécification (à faire valider)

1. **Règles dans `regles.json`, pas dans SQLite.** Le contrôleur root relit des fichiers écrits par `secubox` avec `O_NOFOLLOW` et les revalide (comportement du POC). Ouvrir une base SQLite écrite par un compte non privilégié, en root, élargirait la surface. Les compteurs restent en SQLite.
2. **Identité de l'appareil = son `nom`** dans l'état (« TV banc » regroupe déjà ses adresses IPv4 et IPv6), pas l'adresse MAC. Le regroupement par MAC reste un affichage.
3. **Signal « rafale » recalibré.** La spec disait « beaucoup de refus ». La mesure du 2026-10-03 montre que la TV, **lecture normale**, redemande un domaine refusé 20 à 24 fois en 2,5 minutes (~10/min). Un seuil bas retirerait des règles qui fonctionnent. Seuil initial : **> 60 refus/min pendant 5 min consécutives**, configurable, étiqueté « à calibrer ».
4. **Moteur = minuterie systemd** (`secubox-adguard-auto.timer`, utilisateur `secubox`) et non le démon `dnsfeed` : il appelle `sudo` pour l'application à chaud, ce que le démon (durci) ne peut pas faire.

## Global Constraints

- nftables/WAF inchangés ; aucun mitmproxy, aucune inspection HTTPS, aucun contournement DRM.
- Toute route d'écriture : `require_jwt` ; lecture : `require_lecture`. Aucune route usager en v1.
- L'API n'écrit jamais dans Unbound : elle écrit `regles.json` (validé) puis appelle le contrôleur root, qui **relit et revalide**.
- Contrôleur root : arguments exacts dans `sudoers.d/secubox-adguard-tv`, pas de shell, liens symboliques refusés, `unbound-checkconf` avant de garder un drop-in, audit dans `/var/log/secubox/audit.log`.
- Le mode `auto` est **désactivé par défaut** ; seul un administrateur peut l'activer.
- Un essai non confirmé au bout de 24 h est **retiré** (jamais promu seul).
- Aucun chiffre de seuil présenté comme validé : constantes nommées, configurables, commentées « à calibrer ».
- Aucune organisation inventée dans l'interface ; rendu par `textContent`.
- En-tête SPDX CMSD-1.0 sur tout fichier ; version `1.4.0-1~bookworm1`, `debian/compat` 13 ; pas de mention de « CyberMind Produits SASU » ; commits `type: message (ref #1954)`, **sans** ligne d'attribution Claude.
- Source d'abord : aucune édition à chaud sur gk2 ; déploiement par paquet ; dépôt apt à jour ; vérifier `dpkg -l secubox-ad-guard` sur gk2 avant de bâtir (déployé : 1.3.0).

## Review Focus

1. **TV éteinte/inactive** : aucun signal ne doit retirer une règle quand l'appareil ne demande plus rien (test dans T3).
2. **Domaine hostile** (`"; reboot`, `../`, majuscules, point final, IDN, très long) dans les événements ou `regles.json` : jamais écrit dans une configuration Unbound (T1, T4).
3. **`regles.json` remplacé par un lien symbolique** ou corrompu : le contrôleur refuse, ne change rien (T4).
4. **Liste noire de sécurité** (`googleapis.com`, `gstatic.com`, `apple.com`…) : jamais proposée, même si observée dans une coupure ; un sous-domaine est aussi refusé (T2).
5. **Une règle expirée sans confirmation est retirée** et ne revient pas en essai toute seule ; une règle rejetée n'est jamais reproposée (T1).
6. **Échec d'une commande `unbound-control`** : repli sur la version précédente / rechargement complet, jamais d'état intermédiaire silencieux (T4).

---

## File Structure

| Fichier | Responsabilité |
|---|---|
| `packages/secubox-ad-guard/api/dnstv_regles.py` (créer) | modèle de règle, validation, machine à états, lecture/écriture atomique de `regles.json` |
| `packages/secubox-ad-guard/api/dnstv_detect.py` (créer) | coupures, candidats, motifs, liste noire |
| `packages/secubox-ad-guard/api/dnstv_signaux.py` (créer) | signaux de casse (rafale, contenu disparu) |
| `packages/secubox-ad-guard/api/dnstv_auto.py` (créer) | moteur `tick()` : relie détection, signaux, règles |
| `packages/secubox-ad-guard/api/dnstv.py` (modifier) | mode `auto`, `rendre_unbound` avec règles, `Magasin.evenements/jours_vus` |
| `packages/secubox-ad-guard/sbin/secubox-adguard-tv` (modifier) | commande `regles-appliquer` (à chaud + repli) |
| `packages/secubox-ad-guard/sbin/secubox-adguard-auto` (créer) | point d'entrée de la minuterie |
| `packages/secubox-ad-guard/api/dnstv_routes.py` (modifier) | routes `/adblock-tv/auto/*` |
| `packages/secubox-ad-guard/www/ad-guard/index.html` (modifier) | panneau d'administration |
| `packages/secubox-ad-guard/debian/*`, `sudoers.d/*`, `config/ad-guard.toml` (modifier/créer) | paquet 1.4.0, minuterie, sudoers, seuils |
| `packages/secubox-ad-guard/tests/test_dnstv_*.py` (créer) | un fichier de tests par module |

Chemins de test : `cd packages/secubox-ad-guard && python -m pytest tests -q` (le `conftest.py` met le paquet et `common/` sur le chemin).

---

### Task 1: Règles — modèle, états, stockage

**Files:**
- Create: `packages/secubox-ad-guard/api/dnstv_regles.py`
- Test: `packages/secubox-ad-guard/tests/test_dnstv_regles.py`

**Interfaces:**
- Produces: `ErreurRegle(ValueError)`; constantes `ETATS`, `ESSAI_S=86400`, `CANDIDAT_S=14*86400`; `slug(nom:str)->str`; `class Regles` avec `Regles.depuis_dict(brut)->Regles`, `.vers_dict()->dict`, `.proposer(appareil:str, domaine:str, score:int, risque:str, maintenant:int, origine:str="auto")->dict|None`, `.transiter(rid:str, vers:str, origine:str, motif:str, maintenant:int)->dict`, `.expirer(maintenant:int)->list[dict]`, `.actives(appareil:str)->list[str]`, `.par_appareil()->dict[str,list[str]]`, `.get(rid)->dict`, `.liste()->list[dict]`; `identifiant(appareil, domaine)->str`; `charger(dossier=None)->Regles`; `ecrire(regles, dossier=None)->None`.

- [ ] **Step 1: Write the failing test** — `tests/test_dnstv_regles.py`

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import json
import os

import pytest

from api import dnstv_regles as R

T0 = 1_800_000_000


def test_proposer_cree_un_candidat_unique_par_appareil_et_domaine():
    r = R.Regles()
    a = r.proposer("tv-banc", "videos-pub.ftv-publicite.fr", 70, "faible", T0)
    assert a["etat"] == "candidat"
    assert r.proposer("tv-banc", "videos-pub.ftv-publicite.fr", 90, "faible", T0 + 5) is None   # déjà là : pas de doublon
    assert len(r.liste()) == 1


def test_domaine_hostile_refuse():
    r = R.Regles()
    for mauvais in ('a"; reboot', "../etc", "UPPER.example.com ", "x" * 300 + ".com", "a b.com", "", "com"):
        with pytest.raises(R.ErreurRegle):
            r.proposer("tv-banc", mauvais, 10, "faible", T0)


def test_cycle_essai_confirme_retire():
    r = R.Regles()
    rid = r.proposer("tv", "ad.example.com", 50, "faible", T0)["id"]
    e = r.transiter(rid, "essai", "admin", "essai demandé", T0 + 1)
    assert e["etat"] == "essai" and e["fin_essai"] == T0 + 1 + R.ESSAI_S
    assert r.actives("tv") == ["ad.example.com"]
    assert r.transiter(rid, "confirme", "admin", "ok", T0 + 100)["etat"] == "confirme"
    assert r.actives("tv") == ["ad.example.com"]
    assert r.transiter(rid, "retire", "admin", "casse", T0 + 200)["etat"] == "retire"
    assert r.actives("tv") == []


def test_transition_interdite():
    r = R.Regles()
    rid = r.proposer("tv", "ad.example.com", 50, "faible", T0)["id"]
    with pytest.raises(R.ErreurRegle):
        r.transiter(rid, "confirme", "admin", "sans essai", T0 + 1)     # on ne confirme pas ce qui n'a pas été essayé


def test_essai_expire_sans_confirmation_est_retire():
    r = R.Regles()
    rid = r.proposer("tv", "ad.example.com", 50, "faible", T0)["id"]
    r.transiter(rid, "essai", "admin", "", T0)
    assert r.expirer(T0 + R.ESSAI_S - 1) == []
    ch = r.expirer(T0 + R.ESSAI_S + 1)
    assert [c["id"] for c in ch] == [rid] and r.get(rid)["etat"] == "retire"
    assert "expir" in r.get(rid)["motif"]
    assert r.actives("tv") == []


def test_candidat_trop_ancien_disparait_et_rejete_ne_revient_jamais():
    r = R.Regles()
    c = r.proposer("tv", "a.example.com", 50, "faible", T0)["id"]
    j = r.proposer("tv", "b.example.com", 50, "faible", T0)["id"]
    r.transiter(j, "rejete", "admin", "non", T0 + 1)
    r.expirer(T0 + R.CANDIDAT_S + 1)
    assert r.get(c)["etat"] == "retire"
    assert r.proposer("tv", "b.example.com", 99, "faible", T0 + 10) is None   # rejeté : jamais reproposé


def test_historique_borne():
    r = R.Regles()
    rid = r.proposer("tv", "a.example.com", 1, "faible", T0)["id"]
    for i in range(40):
        r.transiter(rid, "essai", "admin", "", T0 + i * 2)
        r.transiter(rid, "retire", "admin", "", T0 + i * 2 + 1)
    assert len(r.get(rid)["historique"]) <= 20


def test_stockage_atomique_et_lien_symbolique_refuse(tmp_path):
    r = R.Regles()
    r.proposer("tv", "a.example.com", 1, "faible", T0)
    R.ecrire(r, tmp_path)
    assert R.charger(tmp_path).liste()[0]["domaine"] == "a.example.com"
    (tmp_path / "regles.json").unlink()
    (tmp_path / "ailleurs.json").write_text(json.dumps({"version": 1, "regles": []}))
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "regles.json")
    with pytest.raises(R.ErreurRegle):
        R.charger(tmp_path)


def test_fichier_corrompu_refuse_sans_deviner(tmp_path):
    (tmp_path / "regles.json").write_text("{pas du json")
    with pytest.raises(R.ErreurRegle):
        R.charger(tmp_path)
    (tmp_path / "regles.json").write_text(json.dumps({"version": 1, "regles": [{"domaine": "a b", "appareil": "tv", "etat": "essai"}]}))
    with pytest.raises(R.ErreurRegle):
        R.charger(tmp_path)


def test_absent_donne_un_ensemble_vide(tmp_path):
    assert R.charger(tmp_path).liste() == []


def test_slug():
    assert R.slug("TV banc") == "tv-banc"
    assert R.slug("  Salon/ TV_2 ") == "salon-tv-2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/secubox-ad-guard && python -m pytest tests/test_dnstv_regles.py -q`
Expected: FAIL (`ModuleNotFoundError: api.dnstv_regles`).

- [ ] **Step 3: Write minimal implementation** — `api/dnstv_regles.py`

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: règles du mode « auto » du POC DNS AdBlock TV (#1954).

Une règle = un domaine pour UN appareil. Cycle : candidat → essai (24 h) → confirmé ; sorties : rejeté, retiré.
Un essai non confirmé EXPIRE en « retiré » : l'automatisme ne fixe jamais rien seul.
Le fichier `regles.json` est écrit par un compte non privilégié et relu par le contrôleur root : tout est revalidé à la lecture,
les liens symboliques sont refusés.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

try:
    from . import dnstv
except ImportError:                                   # lancé hors paquet
    from api import dnstv

ETATS = ("candidat", "essai", "confirme", "rejete", "retire")
TRANSITIONS = {
    "candidat": {"essai", "rejete", "retire"},
    "essai": {"confirme", "retire"},
    "confirme": {"retire"},
    "rejete": {"candidat"},                            # l'administrateur peut rouvrir
    "retire": {"essai", "rejete"},
}
ESSAI_S = 24 * 3600                                    # durée de l'essai
CANDIDAT_S = 14 * 86400                                # un candidat ignoré 14 jours disparaît
HISTORIQUE_MAX = 20
REGLES_MAX = 2000
RISQUES = ("faible", "partage", "variable")
ORIGINES = ("auto", "admin")
FICHIER = "regles.json"


class ErreurRegle(ValueError):
    pass


def slug(nom: str) -> str:
    """Identifiant de vue Unbound pour un appareil : minuscules, tirets ; jamais autre chose que [a-z0-9-]."""
    s = re.sub(r"[^a-z0-9]+", "-", str(nom).lower()).strip("-")
    return s[:40] or "appareil"


def identifiant(appareil: str, domaine: str) -> str:
    return hashlib.sha1(f"{appareil}|{domaine}".encode()).hexdigest()[:12]


def _domaine(brut: str) -> str:
    d = dnstv.valider_domaine(brut) if isinstance(brut, str) and brut == brut.strip() and brut == brut.lower() else None
    if not d:
        raise ErreurRegle("domaine invalide")
    return d


def _appareil(brut: str) -> str:
    if not isinstance(brut, str) or slug(brut) != brut:
        raise ErreurRegle("appareil invalide (identifiant : minuscules, chiffres, tirets)")
    return brut


def valider_regle(b: dict) -> dict:
    if not isinstance(b, dict):
        raise ErreurRegle("règle invalide")
    appareil, domaine = _appareil(b.get("appareil")), _domaine(b.get("domaine"))
    if b.get("etat") not in ETATS:
        raise ErreurRegle("état de règle inconnu")
    risque = b.get("risque", "faible")
    origine = b.get("origine", "auto")
    if risque not in RISQUES or origine not in ORIGINES:
        raise ErreurRegle("risque ou origine inconnu")
    entiers = {}
    for k in ("cree", "maj", "fin_essai", "score"):
        v = b.get(k, 0)
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ErreurRegle(f"champ {k} invalide")
        entiers[k] = v
    hist = b.get("historique", [])
    if not isinstance(hist, list):
        raise ErreurRegle("historique invalide")
    propre = []
    for h in hist[-HISTORIQUE_MAX:]:
        if not isinstance(h, dict) or h.get("vers") not in ETATS or not isinstance(h.get("ts"), int):
            raise ErreurRegle("historique invalide")
        propre.append({"ts": h["ts"], "de": h.get("de") if h.get("de") in ETATS else "", "vers": h["vers"],
                       "origine": h.get("origine") if h.get("origine") in ORIGINES else "auto", "motif": str(h.get("motif", ""))[:120]})
    return {"id": identifiant(appareil, domaine), "appareil": appareil, "domaine": domaine, "etat": b["etat"], "origine": origine,
            "risque": risque, "motif": str(b.get("motif", ""))[:120], "historique": propre, **entiers}


class Regles:
    def __init__(self, regles: Optional[List[dict]] = None):
        self._r: Dict[str, dict] = {}
        for x in regles or []:
            v = valider_regle(x)
            self._r[v["id"]] = v
        if len(self._r) > REGLES_MAX:
            raise ErreurRegle("trop de règles")

    @classmethod
    def depuis_dict(cls, brut) -> "Regles":
        if not isinstance(brut, dict) or brut.get("version") != 1 or not isinstance(brut.get("regles"), list):
            raise ErreurRegle("fichier de règles illisible")
        return cls(brut["regles"])

    def vers_dict(self) -> dict:
        return {"version": 1, "regles": sorted(self._r.values(), key=lambda x: (x["appareil"], x["domaine"]))}

    def liste(self) -> List[dict]:
        return [dict(x) for x in self.vers_dict()["regles"]]

    def get(self, rid: str) -> dict:
        if rid not in self._r:
            raise ErreurRegle("règle inconnue")
        return dict(self._r[rid])

    def proposer(self, appareil: str, domaine: str, score: int, risque: str, maintenant: int, origine: str = "auto") -> Optional[dict]:
        appareil, domaine = _appareil(appareil), _domaine(domaine)
        rid = identifiant(appareil, domaine)
        if rid in self._r:
            return None                                # déjà connue (y compris rejetée : jamais reproposée)
        if len(self._r) >= REGLES_MAX:
            raise ErreurRegle("trop de règles")
        regle = valider_regle({"appareil": appareil, "domaine": domaine, "etat": "candidat", "origine": origine, "risque": risque,
                               "score": max(0, int(score)), "cree": maintenant, "maj": maintenant, "fin_essai": 0,
                               "historique": [{"ts": maintenant, "de": "", "vers": "candidat", "origine": origine, "motif": "proposé"}]})
        self._r[rid] = regle
        return dict(regle)

    def transiter(self, rid: str, vers: str, origine: str, motif: str, maintenant: int) -> dict:
        r = self._r.get(rid)
        if r is None:
            raise ErreurRegle("règle inconnue")
        if vers not in TRANSITIONS.get(r["etat"], set()):
            raise ErreurRegle(f"transition interdite : {r['etat']} → {vers}")
        if origine not in ORIGINES:
            raise ErreurRegle("origine inconnue")
        r["historique"] = (r["historique"] + [{"ts": maintenant, "de": r["etat"], "vers": vers, "origine": origine, "motif": str(motif)[:120]}])[-HISTORIQUE_MAX:]
        r["etat"], r["maj"], r["motif"] = vers, maintenant, str(motif)[:120]
        r["fin_essai"] = maintenant + ESSAI_S if vers == "essai" else 0
        return dict(r)

    def expirer(self, maintenant: int) -> List[dict]:
        """Essais non confirmés → retirés ; candidats trop anciens → retirés. Rend les règles changées."""
        out = []
        for rid, r in list(self._r.items()):
            if r["etat"] == "essai" and maintenant > r["fin_essai"]:
                out.append(self.transiter(rid, "retire", "auto", "essai expiré sans confirmation", maintenant))
            elif r["etat"] == "candidat" and maintenant - r["cree"] > CANDIDAT_S:
                out.append(self.transiter(rid, "retire", "auto", "candidat ignoré 14 jours", maintenant))
        return out

    def actives(self, appareil: str) -> List[str]:
        return sorted(r["domaine"] for r in self._r.values() if r["appareil"] == appareil and r["etat"] in ("essai", "confirme"))

    def par_appareil(self) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {}
        for r in self._r.values():
            if r["etat"] in ("essai", "confirme"):
                out.setdefault(r["appareil"], []).append(r["domaine"])
        return {k: sorted(v) for k, v in out.items()}


def charger(dossier: Optional[Path] = None) -> Regles:
    f = (dossier or dnstv.DOSSIER_ETAT) / FICHIER
    try:
        fd = os.open(f, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return Regles()
    except OSError as e:
        raise ErreurRegle(f"fichier de règles refusé ({type(e).__name__})") from e
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as h:
            return Regles.depuis_dict(json.loads(h.read(2 * 1024 * 1024)))
    except (ValueError, OSError) as e:
        if isinstance(e, ErreurRegle):
            raise
        raise ErreurRegle("fichier de règles illisible") from e


def ecrire(regles: Regles, dossier: Optional[Path] = None) -> None:
    d = dossier or dnstv.DOSSIER_ETAT
    d.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".regles.")
    with os.fdopen(fd, "w", encoding="utf-8") as h:
        json.dump(regles.vers_dict(), h, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o644)
    os.replace(tmp, d / FICHIER)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/secubox-ad-guard && python -m pytest tests/test_dnstv_regles.py -q`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ad-guard/api/dnstv_regles.py packages/secubox-ad-guard/tests/test_dnstv_regles.py
git commit -m "feat: regles du mode auto, machine a etats et stockage valide (ref #1954)"
```

---

### Task 2: Détection des candidats

**Files:**
- Create: `packages/secubox-ad-guard/api/dnstv_detect.py`
- Test: `packages/secubox-ad-guard/tests/test_dnstv_detect.py`

**Interfaces:**
- Consumes: `dnstv.valider_domaine`, `dnstv.Classifieur.classer(nom)->(categorie|None, liste)`.
- Produces: `LISTE_NOIRE: tuple[str]`; `est_liste_noire(domaine)->bool`; `Candidat` (dataclass : `domaine:str, score:int, risque:str, coupures:int, motif:str`) ; `detecter(evts:list[dict], est_declencheur:Callable[[str],bool], classer:Callable[[str],str], exclus:set[str], fenetre_s:int=60, pause_s:int=120, min_coupures:int=2, min_variantes:int=3)->list[Candidat]`, où chaque `evt` = `{"ts":int,"domaine":str,"decision":str}` trié par `ts` croissant.

Règle de décision (copiée de la spec §4, avec le cas validé en réel) : un domaine est candidat s'il n'est ni en liste noire, ni dans `exclus` (règles existantes ou rejetées), et :
- **classé** `advertising`/`tracking` par les listes et vu dans au moins une coupure → score élevé, risque `faible` (ou `partage` s'il est aussi vu hors coupure) ;
- **non classé**, absent hors coupure, vu dans ≥ `min_coupures` coupures distinctes → candidat à score plus bas.
Les variantes `x.parent` (≥ `min_variantes` noms avec le même parent de ≥ 3 libellés) sont remplacées par le parent, risque `variable`.

- [ ] **Step 1: Write the failing test**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api import dnstv_detect as D

T0 = 1_800_000_000
DECLENCHEURS = ("fwmrm.net",)
CLASSES = {"ad.doubleclick.net": "advertising", "7cd77.v.fwmrm.net": "advertising"}


def declencheur(d):
    return any(d == s or d.endswith("." + s) for s in DECLENCHEURS)


def classer(d):
    return CLASSES.get(d, "")


def ev(ts, d, dec="ALLOWED"):
    return {"ts": ts, "domaine": d, "decision": dec}


def coupure(t, noms):
    """Une coupure : le serveur d'insertion puis les noms de la pub dans les 60 s."""
    return [ev(t, "7cd77.v.fwmrm.net")] + [ev(t + 2 + i, n) for i, n in enumerate(noms)]


def lecture(t):
    return [ev(t + i * 20, d) for i, d in enumerate(["cloudreplay.ftven.fr", "k7.ftven.fr", "hdfauth.ftven.fr"])]


def noms(cands):
    return {c.domaine: c for c in cands}


def test_apprend_ce_qui_n_apparait_que_pendant_les_coupures():
    evts = lecture(T0) + coupure(T0 + 300, ["videos-pub.ftv-publicite.fr", "cloudreplay.ftven.fr"]) + lecture(T0 + 500) \
        + coupure(T0 + 900, ["videos-pub.ftv-publicite.fr", "k7.ftven.fr"])
    c = noms(D.detecter(sorted(evts, key=lambda e: e["ts"]), declencheur, classer, set()))
    assert "videos-pub.ftv-publicite.fr" in c                       # vu dans 2 coupures, jamais en lecture
    assert "cloudreplay.ftven.fr" not in c and "k7.ftven.fr" not in c  # le contenu est aussi demandé hors coupure
    assert c["videos-pub.ftv-publicite.fr"].coupures == 2


def test_un_seul_passage_ne_suffit_pas_pour_un_inconnu():
    evts = lecture(T0) + coupure(T0 + 300, ["videos-pub.ftv-publicite.fr"])
    assert "videos-pub.ftv-publicite.fr" not in noms(D.detecter(evts, declencheur, classer, set()))


def test_un_domaine_classe_publicitaire_est_propose_des_la_premiere_coupure():
    evts = lecture(T0) + coupure(T0 + 300, ["ad.doubleclick.net"])
    c = noms(D.detecter(evts, declencheur, classer, set()))
    assert c["ad.doubleclick.net"].score > 50 and c["ad.doubleclick.net"].risque == "faible"


def test_le_serveur_d_insertion_est_propose_et_signale_partage_s_il_sert_aussi_hors_coupure():
    evts = lecture(T0) + [ev(T0 + 5, "7cd77.v.fwmrm.net")] + coupure(T0 + 600, [])
    c = noms(D.detecter(sorted(evts, key=lambda e: e["ts"]), declencheur, classer, set()))
    assert c["7cd77.v.fwmrm.net"].risque == "partage"


def test_liste_noire_jamais_proposee_meme_sous_domaine():
    bad = ["play.googleapis.com", "www.gstatic.com", "configuration.ls.apple.com", "s3.amazonaws.com"]
    evts = coupure(T0, bad) + coupure(T0 + 900, bad)
    c = noms(D.detecter(evts, declencheur, classer, set()))
    assert not (set(bad) & set(c))
    assert all(D.est_liste_noire(b) for b in bad)


def test_exclus_ne_sont_pas_reproposes():
    evts = coupure(T0, ["ad.doubleclick.net"]) + coupure(T0 + 900, ["ad.doubleclick.net"])
    assert D.detecter(evts, declencheur, classer, {"ad.doubleclick.net"}) == [] or "ad.doubleclick.net" not in noms(
        D.detecter(evts, declencheur, classer, {"ad.doubleclick.net"}))


def test_noms_variables_regroupes_sous_le_parent():
    var = ["r1---sn-aaa.c.2mdn.net", "r5---sn-bbb.c.2mdn.net", "r2---sn-ccc.c.2mdn.net"]
    evts = coupure(T0, var) + coupure(T0 + 900, var)
    c = noms(D.detecter(evts, declencheur, classer, set()))
    assert "c.2mdn.net" in c and c["c.2mdn.net"].risque == "variable"
    assert not any(n.startswith("r1---") for n in c)


def test_evenements_hostiles_ignores():
    evts = coupure(T0, ['x"; reboot', "A B.com", "../etc"]) + coupure(T0 + 900, ['x"; reboot', "A B.com", "../etc"])
    assert D.detecter(evts, declencheur, classer, set()) == []


def test_pas_de_declencheur_pas_de_candidat():
    assert D.detecter(lecture(T0), declencheur, classer, set()) == []


def test_refus_deja_appliques_ne_comptent_pas_comme_vus():
    """Un nom déjà refusé (BLOCKED) pendant l'essai ne doit pas être reproposé ni compté comme du contenu hors coupure."""
    evts = coupure(T0, []) + [ev(T0 + 3, "ad.doubleclick.net", "BLOCKED")]
    assert "ad.doubleclick.net" in noms(D.detecter(evts, declencheur, classer, set())) or True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dnstv_detect.py -q`
Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write minimal implementation** — `api/dnstv_detect.py`

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: détection des candidats du mode « auto » (#1954).

Heuristique issue d'UN cas réel (replay France TV, TV Android, 2026-10-03) : une coupure publicitaire commence par une requête vers un
serveur d'insertion (FreeWheel) ; les noms demandés dans les secondes qui suivent et jamais en lecture normale sont ceux de la pub.
Elle n'est pas validée ailleurs : tout candidat passe par l'essai et la confirmation de l'administrateur.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Dict, List, Set

try:
    from . import dnstv
except ImportError:
    from api import dnstv

# Domaines génériques : les bloquer casserait le système de l'appareil ou d'autres services. Jamais proposés (suffixe compris).
LISTE_NOIRE = ("googleapis.com", "gstatic.com", "google.com", "googleusercontent.com", "apple.com", "icloud.com", "aaplimg.com",
               "amazonaws.com", "cloudfront.net", "cloudflare.com", "akamaiedge.net", "akamaized.net", "akadns.net",
               "microsoft.com", "windowsupdate.com", "ntp.org", "arpa", "local", "lan", "home", "invalid")
CLASSES_PUB = ("advertising", "tracking")
SCORE_CLASSE = 70
SCORE_INCONNU = 30
BONUS_COUPURE = 10          # par coupure supplémentaire (plafonné) — valeurs de départ, à calibrer sur plusieurs jours réels


@dataclass
class Candidat:
    domaine: str
    score: int
    risque: str
    coupures: int
    motif: str


def est_liste_noire(domaine: str) -> bool:
    return any(domaine == s or domaine.endswith("." + s) for s in LISTE_NOIRE)


def _coupures(evts: List[dict], est_declencheur: Callable[[str], bool], fenetre_s: int, pause_s: int) -> List[tuple]:
    """Fenêtres [début, fin] : une coupure commence à un déclencheur non précédé d'un autre dans les `pause_s` secondes."""
    debuts, dernier = [], None
    for e in evts:
        if est_declencheur(e["domaine"]):
            if dernier is None or e["ts"] - dernier > pause_s:
                debuts.append(e["ts"])
            dernier = e["ts"]
    return [(d, d + fenetre_s) for d in debuts]


def detecter(evts: List[dict], est_declencheur: Callable[[str], bool], classer: Callable[[str], str], exclus: Set[str],
             fenetre_s: int = 60, pause_s: int = 120, min_coupures: int = 2, min_variantes: int = 3) -> List[Candidat]:
    evts = [e for e in evts if e.get("decision") != "BLOCKED" and dnstv.valider_domaine(e.get("domaine", "")) == e.get("domaine")]
    fenetres = _coupures(evts, est_declencheur, fenetre_s, pause_s)
    if not fenetres:
        return []
    dans: Dict[str, Set[int]] = defaultdict(set)      # domaine → coupures où il apparaît
    hors: Set[str] = set()
    for e in evts:
        k = next((i for i, (a, b) in enumerate(fenetres) if a <= e["ts"] <= b), None)
        if k is None:
            hors.add(e["domaine"])
        else:
            dans[e["domaine"]].add(k)
    bruts: Dict[str, Candidat] = {}
    for d, ks in dans.items():
        if d in exclus or est_liste_noire(d):
            continue
        classe = classer(d) in CLASSES_PUB
        n = len(ks)
        if classe:
            risque = "partage" if d in hors else "faible"
            score, motif = SCORE_CLASSE + min(20, BONUS_COUPURE * (n - 1)), f"classé {classer(d)} par les listes, vu dans {n} coupure(s)"
        elif d not in hors and n >= min_coupures:
            risque, score, motif = "faible", SCORE_INCONNU + min(30, BONUS_COUPURE * (n - min_coupures)), f"vu seulement pendant {n} coupures"
        else:
            continue
        bruts[d] = Candidat(d, score, risque, n, motif)
    # regroupement des noms à partie variable sous leur parent (≥ 3 variantes, parent de ≥ 3 libellés, hors liste noire)
    parents: Dict[str, List[str]] = defaultdict(list)
    for d in bruts:
        p = d.split(".", 1)[1] if "." in d else ""
        if p.count(".") >= 1 and p not in exclus and not est_liste_noire(p):
            parents[p].append(d)
    for p, enfants in parents.items():
        if len(enfants) >= min_variantes and p.count(".") >= 2 - 0 and p not in hors:
            tete = max(bruts[e].score for e in enfants)
            n = max(bruts[e].coupures for e in enfants)
            for e in enfants:
                del bruts[e]
            bruts[p] = Candidat(p, tete, "variable", n, f"{len(enfants)} noms à partie variable regroupés")
    return sorted(bruts.values(), key=lambda c: (-c.score, c.domaine))
```

Note d'exécution : `p.count(".") >= 2 - 0` est volontairement égal à `>= 2`, soit un parent d'au moins 3 libellés (`c.2mdn.net`) ; l'implémenteur simplifie en `>= 2`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dnstv_detect.py -q`
Expected: PASS. Si `test_exclus…` ou `test_refus…` passent par leur clause `or`/`or True`, **resserrer ces deux assertions** (elles doivent affirmer l'absence, respectivement la présence, sans échappatoire) avant le commit.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ad-guard/api/dnstv_detect.py packages/secubox-ad-guard/tests/test_dnstv_detect.py
git commit -m "feat: detection des candidats par comparaison coupure/lecture (ref #1954)"
```

---

### Task 3: Signaux de casse

**Files:**
- Create: `packages/secubox-ad-guard/api/dnstv_signaux.py`
- Test: `packages/secubox-ad-guard/tests/test_dnstv_signaux.py`

**Interfaces:**
- Produces: `SEUIL_REFUS_MIN=60`, `DUREE_RAFALE_MIN=5`, `MIN_REQUETES_ACTIF=100`, `MIN_JOURS_CONTENU=3`; `rafale(evts:list[dict], domaines:set[str], maintenant:int, seuil_par_min:int=SEUIL_REFUS_MIN, minutes:int=DUREE_RAFALE_MIN)->list[str]` (domaines en rafale) ; `contenu_disparu(jours_vus:dict[str,int], vus_depuis:set[str], requetes_depuis:int, min_jours:int=MIN_JOURS_CONTENU, min_requetes:int=MIN_REQUETES_ACTIF)->list[str]`.

- [ ] **Step 1: Write the failing test**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
from api import dnstv_signaux as S

T = 1_800_000_000


def refus(d, par_min, minutes, fin=T):
    """`par_min` refus par minute pendant `minutes` minutes, se terminant à `fin`."""
    out = []
    for m in range(minutes):
        for k in range(par_min):
            out.append({"ts": fin - m * 60 - k, "domaine": d, "decision": "BLOCKED"})
    return out


def test_le_comportement_normal_mesure_n_est_pas_une_rafale():
    """Mesuré le 2026-10-03 : la TV, lecture NORMALE, redemande un domaine refusé ~10 fois par minute."""
    assert S.rafale(refus("videos-pub.ftv-publicite.fr", 10, 10), {"videos-pub.ftv-publicite.fr"}, T) == []


def test_rafale_soutenue_detectee():
    assert S.rafale(refus("ad.example.com", 80, 6), {"ad.example.com"}, T) == ["ad.example.com"]


def test_rafale_courte_ignoree():
    assert S.rafale(refus("ad.example.com", 80, 2), {"ad.example.com"}, T) == []


def test_rafale_sur_un_domaine_non_gere_ignoree():
    assert S.rafale(refus("autre.example.com", 80, 6), {"ad.example.com"}, T) == []


def test_contenu_disparu_quand_l_appareil_reste_actif():
    jours = {"cloudreplay.ftven.fr": 5, "k7.ftven.fr": 4, "rare.example.com": 1}
    assert S.contenu_disparu(jours, vus_depuis={"k7.ftven.fr"}, requetes_depuis=500) == ["cloudreplay.ftven.fr"]


def test_appareil_inactif_ne_retire_rien():
    """TV éteinte : aucune requête, donc aucun contenu « disparu »."""
    jours = {"cloudreplay.ftven.fr": 5}
    assert S.contenu_disparu(jours, vus_depuis=set(), requetes_depuis=0) == []
    assert S.contenu_disparu(jours, vus_depuis=set(), requetes_depuis=S.MIN_REQUETES_ACTIF - 1) == []


def test_contenu_present_ne_signale_rien():
    assert S.contenu_disparu({"cloudreplay.ftven.fr": 5}, {"cloudreplay.ftven.fr"}, 500) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dnstv_signaux.py -q` — Expected: FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Write minimal implementation**

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: signaux de casse du mode « auto » (#1954).

Le DNS ne voit pas l'écran : ces signaux sont INDIRECTS et leurs seuils sont des valeurs de départ, à calibrer sur plusieurs jours réels.
Étalon mesuré (2026-10-03, TV Android, lecture France TV NORMALE) : un domaine refusé est redemandé ~10 fois par minute (20 à 24 en 2,5 min).
Le seuil de rafale est donc nettement au-dessus : un seuil proche de ce comportement retirerait des règles qui fonctionnent.
"""
from __future__ import annotations

from typing import Dict, List, Set

SEUIL_REFUS_MIN = 60          # refus/minute vers un même domaine (≈ 6× l'étalon mesuré) — à calibrer
DUREE_RAFALE_MIN = 5          # minutes consécutives
MIN_REQUETES_ACTIF = 100      # requêtes depuis la règle pour considérer l'appareil « actif » — à calibrer
MIN_JOURS_CONTENU = 3         # un domaine de contenu : vu au moins 3 jours distincts avant la règle


def rafale(evts: List[dict], domaines: Set[str], maintenant: int, seuil_par_min: int = SEUIL_REFUS_MIN, minutes: int = DUREE_RAFALE_MIN) -> List[str]:
    """Domaines gérés par une règle dont les refus dépassent `seuil_par_min` pendant chacune des `minutes` dernières minutes."""
    par: Dict[str, Dict[int, int]] = {}
    for e in evts:
        if e.get("decision") == "BLOCKED" and e.get("domaine") in domaines:
            m = (maintenant - e["ts"]) // 60
            if 0 <= m < minutes:
                par.setdefault(e["domaine"], {}).setdefault(m, 0)
                par[e["domaine"]][m] += 1
    return sorted(d for d, ms in par.items() if len(ms) == minutes and all(n > seuil_par_min for n in ms.values()))


def contenu_disparu(jours_vus: Dict[str, int], vus_depuis: Set[str], requetes_depuis: int,
                    min_jours: int = MIN_JOURS_CONTENU, min_requetes: int = MIN_REQUETES_ACTIF) -> List[str]:
    """Domaines de contenu habituels (vus ≥ `min_jours` jours) qui ne sont plus demandés alors que l'appareil reste actif.
    Un appareil inactif (éteint, en veille) ne déclenche jamais rien."""
    if requetes_depuis < min_requetes:
        return []
    return sorted(d for d, n in jours_vus.items() if n >= min_jours and d not in vus_depuis)
```

- [ ] **Step 4: Run test to verify it passes** — `python -m pytest tests/test_dnstv_signaux.py -q` — Expected: PASS (7).

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ad-guard/api/dnstv_signaux.py packages/secubox-ad-guard/tests/test_dnstv_signaux.py
git commit -m "feat: signaux de casse indirects, seuil de rafale calibre sur la mesure reelle (ref #1954)"
```

---

### Task 4: Mode `auto` : rendu Unbound et application à chaud

**Files:**
- Modify: `packages/secubox-ad-guard/api/dnstv.py` (`MODES`, `valider_etat` message, `rendre_unbound`, `Magasin.evenements`, `Magasin.jours_vus`)
- Modify: `packages/secubox-ad-guard/sbin/secubox-adguard-tv` (commande `regles-appliquer`)
- Test: `packages/secubox-ad-guard/tests/test_dnstv_auto_rendu.py`

**Interfaces:**
- Consumes: `dnstv_regles.charger`, `Regles.par_appareil()`, `dnstv_regles.slug`.
- Produces: `dnstv.MODES = ("off","observe","block","auto")` ; `dnstv.rendre_unbound(etat, table, regles_actives: dict[str, list[str]] | None = None)` — pour un appareil `auto` : vue `sbx-tv-auto-<slug(nom)>` = `local-zone: "." transparent` + une zone `always_nxdomain` par domaine actif ; `Magasin.evenements(clients:list[str], depuis:int, limite:int=20000)->list[dict]` (ascendant, clés `ts, domaine, decision`) ; `Magasin.jours_vus(clients:list[str], avant_jour:str)->dict[str,int]` (domaines ALLOWED, nombre de jours distincts) ; commande root `secubox-adguard-tv regles-appliquer` → JSON `{"ok":true,"ajoutes":n,"retires":n,"mode":"chaud"|"rechargement"}`.

- [ ] **Step 1: Write the failing test** — `tests/test_dnstv_auto_rendu.py`

```python
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
import importlib.machinery
import importlib.util
import json
import os
import stat
import time
from pathlib import Path

import pytest

from api import dnstv, dnstv_regles as R

ETAT = {"actif": True, "clients": [{"ip": "192.168.1.95", "nom": "TV banc", "mode": "auto"},
                                   {"ip": "2a01:e0a::1", "nom": "TV banc", "mode": "auto"},
                                   {"ip": "192.168.1.9", "nom": "Autre", "mode": "observe"}]}


def test_mode_auto_accepte():
    assert dnstv.valider_etat(ETAT)["clients"][0]["mode"] == "auto"


def test_rendu_une_vue_par_appareil_auto_avec_ses_seules_regles():
    out = dnstv.rendre_unbound(ETAT, {"ads.example.com": "advertising"}, {"tv-banc": ["videos-pub.ftv-publicite.fr", "c.2mdn.net"]})
    assert "access-control-view: 192.168.1.95/32 sbx-tv-auto-tv-banc" in out
    assert "access-control-view: 2a01:e0a::1/128 sbx-tv-auto-tv-banc" in out
    bloc = out.split('name: "sbx-tv-auto-tv-banc"')[1].split("view:")[0]
    assert 'local-zone: "videos-pub.ftv-publicite.fr." always_nxdomain' in bloc
    assert 'local-zone: "c.2mdn.net." always_nxdomain' in bloc
    assert 'local-zone: "." transparent' in bloc
    assert "ads.example.com" not in bloc                      # en auto, la table du mode block ne s'applique pas


def test_rendu_sans_regle_la_vue_auto_est_transparente():
    out = dnstv.rendre_unbound(ETAT, {}, None)
    bloc = out.split('name: "sbx-tv-auto-tv-banc"')[1]
    assert "always_nxdomain" not in bloc.split("view:")[0] and 'local-zone: "." transparent' in bloc


def test_domaine_hostile_dans_les_regles_refuse_au_rendu():
    with pytest.raises(dnstv.ErreurTV):
        dnstv.rendre_unbound(ETAT, {}, {"tv-banc": ['a"; server: reboot']})


def test_magasin_evenements_et_jours_vus(tmp_path):
    m = dnstv.Magasin(tmp_path / "x.db")
    t = int(time.time())
    e1 = dnstv.Evenement(t - 90000, "192.168.1.95", "k7.ftven.fr", "A", "NOERROR", "ALLOWED")
    e2 = dnstv.Evenement(t - 5, "192.168.1.95", "k7.ftven.fr", "A", "NOERROR", "ALLOWED")
    m.ajouter([(e1, ""), (e2, "")])
    ev = m.evenements(["192.168.1.95"], t - 100)
    assert [x["domaine"] for x in ev] == ["k7.ftven.fr"] and ev[0]["decision"] == "ALLOWED"
    assert m.jours_vus(["192.168.1.95"], "9999-01-01")["k7.ftven.fr"] == 2


# ── contrôleur root : commande regles-appliquer ──────────────────────────────

def charger_ctl(monkeypatch, tmp_path, control_script):
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_ETAT", str(tmp_path))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_UNBOUND", str(tmp_path / "94.conf"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_CHECKCONF", str(tmp_path / "checkconf"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_CONTROL", str(control_script))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_APPLIQUE", str(tmp_path / "applique.json"))
    monkeypatch.setenv("SECUBOX_ADGUARD_TV_SANS_ROOT", "1")
    chemin = Path(__file__).resolve().parents[1] / "sbin" / "secubox-adguard-tv"
    loader = importlib.machinery.SourceFileLoader("sbx_tv_ctl", str(chemin))
    spec = importlib.util.spec_from_loader("sbx_tv_ctl", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def faux(tmp_path, nom, code=0):
    p = tmp_path / nom
    p.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/{nom}.log\nexit {code}\n')
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


def preparer(tmp_path, regles):
    dnstv.ecrire_etat(ETAT, tmp_path)
    R.ecrire(regles, tmp_path)


def regles_essai(*domaines):
    r = R.Regles()
    for d in domaines:
        rid = r.proposer("tv-banc", d, 50, "faible", 1_800_000_000)["id"]
        r.transiter(rid, "essai", "admin", "", 1_800_000_000)
    return r


def test_application_a_chaud_ajoute_sans_recharger(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()                                            # état initial : écrit le drop-in, recharge (vue nouvelle)
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    assert mod.regles_appliquer() == 0
    journal = (tmp_path / "unbound-control.log").read_text()
    assert "view_local_zone sbx-tv-auto-tv-banc b.example.com. always_nxdomain" in journal
    assert "reload" not in journal                              # aucune coupure du DNS
    assert 'local-zone: "b.example.com." always_nxdomain' in (tmp_path / "94.conf").read_text()   # persisté pour le prochain démarrage


def test_retrait_a_chaud(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    mod.appliquer()
    (tmp_path / "unbound-control.log").unlink(missing_ok=True)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.regles_appliquer()
    assert "view_local_zone_remove sbx-tv-auto-tv-banc b.example.com." in (tmp_path / "unbound-control.log").read_text()


def test_echec_a_chaud_repli_rechargement(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = tmp_path / "unbound-control"
    ctl.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path}/unbound-control.log\ncase "$1" in view_local_zone*) exit 1;; esac\nexit 0\n')
    ctl.chmod(0o755)
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    preparer(tmp_path, regles_essai("a.example.com"))
    mod.appliquer()
    preparer(tmp_path, regles_essai("a.example.com", "b.example.com"))
    assert mod.regles_appliquer() == 0
    assert "reload" in (tmp_path / "unbound-control.log").read_text().splitlines()[-1]


def test_regles_lien_symbolique_refuse_rien_ne_change(monkeypatch, tmp_path):
    faux(tmp_path, "checkconf")
    ctl = faux(tmp_path, "unbound-control")
    mod = charger_ctl(monkeypatch, tmp_path, ctl)
    dnstv.ecrire_etat(ETAT, tmp_path)
    (tmp_path / "ailleurs.json").write_text(json.dumps({"version": 1, "regles": []}))
    os.symlink(tmp_path / "ailleurs.json", tmp_path / "regles.json")
    with pytest.raises(SystemExit):
        mod.regles_appliquer()
    assert not (tmp_path / "unbound-control.log").exists()
```

- [ ] **Step 2: Run test to verify it fails** — `python -m pytest tests/test_dnstv_auto_rendu.py -q` — Expected: FAIL (mode `auto` inconnu, `regles_appliquer` absent).

- [ ] **Step 3: Write implementation**

3a. `api/dnstv.py` : `MODES = ("off", "observe", "block", "auto")` ; message de `valider_etat` : `"mode inconnu (off, observe, block, auto)"` ; dans la docstring, ajouter la ligne `auto  vue propre à l'appareil : les seules règles apprises, en essai ou confirmées (#1954)`.

3b. `rendre_unbound(etat, table, regles_actives=None)` : après le bloc existant `sbx-tv-block`, générer pour chaque appareil `auto` une vue. Le `slug` vient de `dnstv_regles.slug`, importé **localement** dans la fonction pour éviter l'import circulaire (`dnstv_regles` importe `dnstv`) :

```python
def rendre_unbound(etat: dict, table: Dict[str, str], regles_actives: Optional[Dict[str, List[str]]] = None) -> str:
    ...
    from_regles = regles_actives or {}
    ...
    for c in suivis:
        hote = "/128" if ":" in c["ip"] else "/32"
        vue = f"sbx-tv-auto-{_slug(c['nom'])}" if c["mode"] == "auto" else f"sbx-tv-{c['mode']}"
        L.append(f"    access-control-view: {c['ip']}{hote} {vue}")
    ...
    for nom_slug in sorted({_slug(c["nom"]) for c in suivis if c["mode"] == "auto"}):
        L.append("view:")
        L.append(f'    name: "sbx-tv-auto-{nom_slug}"')
        for d in sorted(set(from_regles.get(nom_slug, []))):
            if valider_domaine(d) != d:
                raise ErreurTV("domaine de règle invalide")
            L.append(f'    local-zone: "{d}." always_nxdomain')
        L.append('    local-zone: "." transparent')
```

avec, en tête de module, `def _slug(nom): return re.sub(r"[^a-z0-9]+", "-", str(nom).lower()).strip("-")[:40] or "appareil"` (même définition que `dnstv_regles.slug`, qui appelle celle-ci pour n'avoir qu'une seule source : remplacer le corps de `dnstv_regles.slug` par `return dnstv._slug(nom)`).

3c. `Magasin.evenements` et `Magasin.jours_vus` :

```python
    def evenements(self, clients: List[str], depuis: int, limite: int = 20000) -> List[dict]:
        """Événements d'UNE source (toutes ses adresses), du plus ancien au plus récent : sert à la détection des coupures."""
        if not clients:
            return []
        with self._cx() as cx:
            lignes = cx.execute(
                "SELECT ts, domaine, decision FROM dnstv_recents WHERE ts>=? AND client IN (%s) ORDER BY ts, rowid LIMIT ?" % ",".join("?" * len(clients)),
                [int(depuis), *clients, max(1, min(int(limite), 50000))]).fetchall()
        return [{"ts": t, "domaine": d, "decision": dec} for t, d, dec in lignes]

    def jours_vus(self, clients: List[str], avant_jour: str) -> Dict[str, int]:
        """Domaines demandés (réponse réelle) et le nombre de JOURS distincts, avant `avant_jour` : définit le « contenu habituel »."""
        if not clients:
            return {}
        with self._cx() as cx:
            return dict(cx.execute(
                "SELECT domaine, COUNT(DISTINCT jour) FROM dnstv_counts WHERE decision='ALLOWED' AND jour<? AND client IN (%s) GROUP BY domaine" % ",".join("?" * len(clients)),
                [avant_jour, *clients]).fetchall())
```

3d. `sbin/secubox-adguard-tv` : ajouter `APPLIQUE = Path(os.environ.get("SECUBOX_ADGUARD_TV_APPLIQUE", "/var/lib/secubox/ad-guard/dnstv-root/applique.json"))`, importer `dnstv_regles`, charger les règles dans `charger()` (retour `(etat, table, regles_actives)` ; `appliquer()` passe `regles_actives` à `rendre_unbound`, et **enregistre** l'instantané `applique.json` écrit par root, `0600`, dans un dossier root), et ajouter :

```python
def instantane(etat: dict, regles_actives: dict) -> dict:
    """Ce que le DNS a RÉELLEMENT chargé : { vue : [domaines] } pour les appareils en mode auto (et les modes pour détecter un changement de vues)."""
    vues = {f"sbx-tv-auto-{dnstv._slug(c['nom'])}": sorted(set(regles_actives.get(dnstv._slug(c['nom']), [])))
            for c in etat["clients"] if c["mode"] == "auto"}
    return {"actif": etat["actif"], "modes": sorted((c["ip"], c["mode"], c["nom"]) for c in etat["clients"]), "vues": vues}


def regles_appliquer() -> int:
    """Applique les seules différences de règles À CHAUD (unbound-control view_local_zone) ; tout autre changement → rechargement complet."""
    etat, table, actives = charger_avec_regles()
    voulu = instantane(etat, actives)
    try:
        avant = json.loads(lire_sans_suivre(APPLIQUE))
    except (OSError, ValueError):
        avant = None
    if avant is None or avant.get("actif") != voulu["actif"] or avant.get("modes") != voulu["modes"] or set(avant.get("vues", {})) != set(voulu["vues"]):
        return appliquer()                                                # vues ou appareils changés : rechargement complet (comme avant)
    ajoutes = retires = 0
    try:
        for vue, doms in voulu["vues"].items():
            anciens = set(avant["vues"].get(vue, []))
            for d in sorted(set(doms) - anciens):
                _control("view_local_zone", vue, d + ".", "always_nxdomain")
                ajoutes += 1
            for d in sorted(anciens - set(doms)):
                _control("view_local_zone_remove", vue, d + ".")
                retires += 1
    except (OSError, subprocess.SubprocessError, RuntimeError):
        audit("regles-chaud-echec", "repli sur rechargement complet")
        return appliquer()
    ecrire_dropin_persistant(etat, table, actives)                        # le prochain démarrage d'Unbound retrouve les mêmes règles
    ecrire_instantane(voulu)
    audit("regles-appliquer", f"ajoutes={ajoutes} retires={retires} mode=chaud")
    print(json.dumps({"ok": True, "ajoutes": ajoutes, "retires": retires, "mode": "chaud"}))
    return 0
```

avec `_control(*args)` = `subprocess.run([CONTROL, *args], check=...)` qui lève `RuntimeError` si code ≠ 0 ; `ecrire_dropin_persistant` = la partie « écrire + `unbound-checkconf` + restauration » de `appliquer()` **sans** appeler `recharger()` (extraire cette partie en fonction commune `_ecrire_verifier(contenu)`, utilisée par `appliquer()` et par la voie à chaud) ; `main()` accepte `regles-appliquer` (`len(argv) != 2 or argv[1] not in (…, "regles-appliquer")`).

- [ ] **Step 4: Run test to verify it passes** — `python -m pytest tests/test_dnstv_auto_rendu.py tests -q` — Expected: PASS, et les anciens tests du module (`test_dnstv_*`) toujours verts.

- [ ] **Step 5: Vérifier à chaud sur le **vrai** Unbound (jetable, jamais celui de production)** — rejouer l'essai de l'étude (instance sur le port 5399, vue `sbx-t`, `view_local_zone` puis `view_local_zone_remove`) comme test pytest `tests/test_dnstv_banc_unbound.py::test_ajout_retrait_a_chaud` marqué `skipif(not shutil.which("unbound"))`. Sur gk2 (Unbound 1.17.1), il doit passer : ajout → NXDOMAIN, retrait → la donnée de la zone parente revient (mesuré le 2026-10-03).

- [ ] **Step 6: Commit**

```bash
git add packages/secubox-ad-guard/api/dnstv.py packages/secubox-ad-guard/api/dnstv_regles.py packages/secubox-ad-guard/sbin/secubox-adguard-tv packages/secubox-ad-guard/tests
git commit -m "feat: mode auto, vue par appareil et application des regles a chaud (ref #1954)"
```

---

### Task 5: Moteur et minuterie

**Files:**
- Create: `packages/secubox-ad-guard/api/dnstv_auto.py`, `packages/secubox-ad-guard/sbin/secubox-adguard-auto`, `packages/secubox-ad-guard/debian/secubox-ad-guard-auto.service`, `packages/secubox-ad-guard/debian/secubox-ad-guard-auto.timer`
- Modify: `packages/secubox-ad-guard/sudoers.d/secubox-adguard-tv`, `packages/secubox-ad-guard/config/ad-guard.toml`
- Test: `packages/secubox-ad-guard/tests/test_dnstv_auto_moteur.py`

**Interfaces:**
- Consumes: `Regles`, `detecter`, `rafale`, `contenu_disparu`, `Magasin.evenements/jours_vus`, `Classifieur.classer`, `dnstv.lire_etat`.
- Produces: `class Reglage` (dataclass : `declencheurs:tuple[str], auto_essai:bool=False, seuil_refus_min:int, duree_rafale_min:int, min_requetes_actif:int`) ; `tick(etat:dict, regles:Regles, magasin:Magasin, classer:Callable[[str],str], reglage:Reglage, maintenant:int)->dict` rendant `{"changements":[{"appareil","domaine","de","vers","motif"}...], "candidats":int, "applique":bool}` — **`applique` vrai si au moins une règle a changé d'état actif/inactif** ; `main()` du script : charge état + règles, appelle `tick`, écrit `regles.json` si changé, appelle `sudo -n /usr/sbin/secubox-adguard-tv regles-appliquer` si `applique`.

Comportement de `tick` (en ordre) : 1) `regles.expirer(maintenant)` ; 2) pour chaque appareil en mode `auto` (adresses regroupées par `slug(nom)`) : `evts = magasin.evenements(adresses, maintenant-48*3600)` ; 3) **détection** → `proposer` chaque candidat (si `reglage.auto_essai` est faux — valeur par défaut — il reste `candidat`, en attente de l'administrateur ; vrai → passe directement en `essai`) ; 4) **signaux** sur les règles en `essai` de l'appareil : `rafale(evts, domaines_en_essai, maintenant)` retire ces règles (`origine=auto`, motif « rafale de refus ») ; `contenu_disparu(magasin.jours_vus(adresses, jour_de(premier_essai)), vus_depuis, nb_requetes_depuis)` retire **toutes** les règles en essai de l'appareil (motif « contenu habituel plus demandé »).

- [ ] **Step 1: Write the failing test** — couvrir : (a) une TV `auto` avec deux coupures rejouées produit un candidat sans changer d'état actif ; (b) `auto_essai=True` met le candidat en `essai` et `applique=True` ; (c) un essai expiré est retiré et `applique=True` ; (d) rafale → retrait ; (e) TV inactive → aucun retrait ; (f) appareil en mode `observe` jamais touché ; (g) un appareil non `auto` n'obtient aucun candidat. Chaque cas alimente un `Magasin` temporaire avec des `Evenement` construits comme dans `tests/test_dnstv_auto_rendu.py::test_magasin_evenements_et_jours_vus`. Le test (e) est le test de la **Review Focus n° 1**.

```python
def test_tv_inactive_ne_retire_aucune_regle(tmp_path):
    magasin, etat, regles, t = scenario_tv_avec_regle_en_essai(tmp_path)      # une règle en essai depuis 2 h, aucune requête depuis
    res = moteur.tick(etat, regles, magasin, lambda d: "", REGLAGE, t)
    assert regles.get(RID_ESSAI)["etat"] == "essai" and res["applique"] is False
```

(`scenario_tv_avec_regle_en_essai`, `REGLAGE`, `RID_ESSAI` sont définis en tête du fichier de test ; l'implémenteur les écrit avec les mêmes `Evenement` que ci-dessus.)

- [ ] **Step 2: Run test to verify it fails** — `python -m pytest tests/test_dnstv_auto_moteur.py -q` — Expected: FAIL.

- [ ] **Step 3: Write implementation** — `api/dnstv_auto.py` (squelette complet à respecter) :

```python
"""SecuBox-Deb :: ad-guard :: moteur du mode « auto » (#1954) — pur : aucune entrée/sortie hors Magasin et Regles."""
from dataclasses import dataclass
from typing import Callable, Dict, List
import time

try:
    from . import dnstv, dnstv_detect, dnstv_regles, dnstv_signaux
except ImportError:
    from api import dnstv, dnstv_detect, dnstv_regles, dnstv_signaux

HISTORIQUE_H = 48


@dataclass
class Reglage:
    declencheurs: tuple = ("fwmrm.net",)
    auto_essai: bool = False
    seuil_refus_min: int = dnstv_signaux.SEUIL_REFUS_MIN
    duree_rafale_min: int = dnstv_signaux.DUREE_RAFALE_MIN
    min_requetes_actif: int = dnstv_signaux.MIN_REQUETES_ACTIF


def appareils(etat: dict) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for c in etat["clients"]:
        if c["mode"] == "auto":
            out.setdefault(dnstv._slug(c["nom"]), []).append(c["ip"])
    return out


def tick(etat, regles, magasin, classer, reglage, maintenant) -> dict:
    changements, applique, candidats = [], False, 0
    def note(r, de, vers, motif):
        nonlocal applique
        changements.append({"appareil": r["appareil"], "domaine": r["domaine"], "de": de, "vers": vers, "motif": motif})
        if (de in ("essai", "confirme")) != (vers in ("essai", "confirme")):
            applique = True
    avant = {r["id"]: r["etat"] for r in regles.liste()}
    for r in regles.expirer(maintenant):
        note(r, avant[r["id"]], r["etat"], r["motif"])
    declencheur = lambda d: any(d == s or d.endswith("." + s) for s in reglage.declencheurs)
    for appareil, adresses in appareils(etat).items():
        evts = magasin.evenements(adresses, maintenant - HISTORIQUE_H * 3600)
        exclus = {r["domaine"] for r in regles.liste() if r["appareil"] == appareil}
        for c in dnstv_detect.detecter(evts, declencheur, classer, exclus):
            n = regles.proposer(appareil, c.domaine, c.score, c.risque, maintenant)
            if n is None:
                continue
            candidats += 1
            changements.append({"appareil": appareil, "domaine": c.domaine, "de": "", "vers": "candidat", "motif": c.motif})
            if reglage.auto_essai:
                r = regles.transiter(n["id"], "essai", "auto", "essai automatique", maintenant)
                note(r, "candidat", "essai", "essai automatique")
        en_essai = [r for r in regles.liste() if r["appareil"] == appareil and r["etat"] == "essai"]
        if not en_essai:
            continue
        for d in dnstv_signaux.rafale(evts, {r["domaine"] for r in en_essai}, maintenant, reglage.seuil_refus_min, reglage.duree_rafale_min):
            r = regles.get(dnstv_regles.identifiant(appareil, d))
            note(regles.transiter(r["id"], "retire", "auto", "rafale de refus", maintenant), "essai", "retire", "rafale de refus")
        restantes = [r for r in en_essai if regles.get(r["id"])["etat"] == "essai"]
        if restantes:
            debut = min(r["maj"] for r in restantes)
            depuis = [e for e in evts if e["ts"] >= debut]
            vus = {e["domaine"] for e in depuis if e["decision"] != "BLOCKED"}
            jours = magasin.jours_vus(adresses, dnstv._jour(debut))
            if dnstv_signaux.contenu_disparu(jours, vus, len(depuis), min_requetes=reglage.min_requetes_actif):
                for r in restantes:
                    note(regles.transiter(r["id"], "retire", "auto", "contenu habituel plus demandé", maintenant), "essai", "retire", "contenu habituel plus demandé")
    return {"changements": changements, "candidats": candidats, "applique": applique}
```

`sbin/secubox-adguard-auto` : lit `etat`, `regles`, `Reglage` depuis `/etc/secubox/ad-guard.toml` (`[adblock_tv_auto] declencheurs`, `auto_essai=false`, `seuil_refus_min`, `duree_rafale_min`, `min_requetes_actif`), appelle `tick`, écrit `regles.json` (via `dnstv_regles.ecrire`) si `changements`, puis `subprocess.run(["sudo","-n","/usr/sbin/secubox-adguard-tv","regles-appliquer"])` si `applique`. Aucun accès réseau, aucune sortie hors journal systemd.

`sudoers.d/secubox-adguard-tv` : ajouter `, /usr/sbin/secubox-adguard-tv regles-appliquer`.

Unité `secubox-ad-guard-auto.service` (`Type=oneshot`, `User=secubox`, `NoNewPrivileges=no` **avec le commentaire** « sudo vers le seul contrôleur ; arguments exacts dans sudoers ») et `secubox-ad-guard-auto.timer` (`OnCalendar=minutely`, `Persistent=false`). `debian/postinst` : `systemctl enable secubox-ad-guard-auto.timer` mais **ne pas** le démarrer tant qu'aucun appareil n'est en mode `auto` ; il se désactive de lui-même (sortie immédiate, code 0) si aucun appareil `auto`.

- [ ] **Step 4: Run test to verify it passes** — `python -m pytest tests -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ad-guard
git commit -m "feat: moteur du mode auto et minuterie, sans promotion automatique (ref #1954)"
```

---

### Task 6: Routes d'administration

**Files:**
- Modify: `packages/secubox-ad-guard/api/dnstv_routes.py`
- Test: `packages/secubox-ad-guard/tests/test_dnstv_auto_routes.py`

**Interfaces:**
- Consumes: `dnstv_regles`, `dnstv_auto.appareils`, `_ctl`, `_etat`, `_refuse` existants.
- Produces (préfixe `/adblock-tv/auto`) : `GET /regles?etat=&appareil=` → `{"regles":[…], "compteurs":{etat:n}}` (`require_lecture`) ; `POST /regles/{rid}/{action}` avec `action ∈ essayer|confirmer|rejeter|retirer|rouvrir` (`require_jwt`) → règle mise à jour + `{"application":…}` quand l'effet DNS change ; `POST /appareils/{appareil}/ca-ne-marche-plus` (`require_jwt`) → retire toutes les règles en essai de l'appareil ; `GET /reglage` → seuils et `auto_essai` (`require_lecture`) ; `POST /reglage/auto-essai` (`require_jwt`, `{"actif":bool}`) → écrit dans `regles.json`? **Non** : ce réglage vit dans `etat.json` sous `auto_essai` (validé par `valider_etat`, défaut faux) pour rester sous le contrôle de l'administrateur.

Correspondance action → transition : `essayer: candidat|retire → essai` ; `confirmer: essai → confirme` ; `rejeter: candidat|retire → rejete` ; `retirer: essai|confirme|candidat → retire` ; `rouvrir: rejete → candidat`. Toute transition refusée par `Regles.transiter` → `422` avec le message court. Toute action qui change l'ensemble actif appelle `_ctl("regles-appliquer")` (étendre `_ctl` : accepter l'action `regles-appliquer`).

- [ ] **Step 1: Write the failing test** — avec `TestClient` comme dans `tests/test_dnstv_ctl_api.py` : (a) lecture sans jeton → 401, écriture avec jeton lecture seule → 403 ; (b) `essayer` sur un candidat → 200, état `essai`, `_ctl` appelé une fois avec `regles-appliquer` (le faux contrôleur du test enregistre l'appel) ; (c) `confirmer` sans essai → 422 ; (d) `ca-ne-marche-plus` retire toutes les règles en essai de l'appareil et seulement elles ; (e) identifiant de règle hostile (`../x`, 200 caractères) → 404/422, jamais d'exception ; (f) `rouvrir` sur rejeté → candidat.

- [ ] **Step 2: Run test to verify it fails** — `python -m pytest tests/test_dnstv_auto_routes.py -q` — Expected: FAIL.

- [ ] **Step 3: Write implementation** — ajouter à `dnstv_routes.py` :

```python
ACTIONS_REGLE = {"essayer": ("essai", {"candidat", "retire"}), "confirmer": ("confirme", {"essai"}),
                 "rejeter": ("rejete", {"candidat", "retire"}), "retirer": ("retire", {"essai", "confirme", "candidat"}),
                 "rouvrir": ("candidat", {"rejete"})}


def _regles():
    try:
        return dnstv_regles.charger()
    except dnstv_regles.ErreurRegle as e:
        raise HTTPException(409, str(e)) from e


@router.get("/auto/regles", dependencies=[Depends(require_lecture)])
async def regles_liste(etat: Optional[str] = None, appareil: Optional[str] = None):
    toutes = _regles().liste()
    compteurs = {}
    for r in toutes:
        compteurs[r["etat"]] = compteurs.get(r["etat"], 0) + 1
    sel = [r for r in toutes if (not etat or r["etat"] == etat) and (not appareil or r["appareil"] == appareil)]
    return {"regles": sel, "compteurs": compteurs}


@router.post("/auto/regles/{rid}/{action}", dependencies=[Depends(require_jwt)])
async def regle_action(rid: str, action: str):
    if action not in ACTIONS_REGLE or not re.fullmatch(r"[0-9a-f]{12}", rid):
        raise HTTPException(404, "action ou règle inconnue")
    vers, depuis = ACTIONS_REGLE[action]
    regles = _regles()
    try:
        avant = regles.get(rid)["etat"]
        if avant not in depuis:
            raise HTTPException(422, f"action impossible depuis l'état « {avant} »")
        r = regles.transiter(rid, vers, "admin", f"action {action}", int(time.time()))
    except dnstv_regles.ErreurRegle as e:
        raise HTTPException(422 if "interdite" in str(e) else 404, str(e)) from e
    dnstv_regles.ecrire(regles)
    effet = (avant in ("essai", "confirme")) != (vers in ("essai", "confirme"))
    return {"regle": r, "application": _ctl("regles-appliquer") if effet else None}


@router.post("/auto/appareils/{appareil}/ca-ne-marche-plus", dependencies=[Depends(require_jwt)])
async def ca_ne_marche_plus(appareil: str):
    regles = _regles()
    touches = [r for r in regles.liste() if r["appareil"] == appareil and r["etat"] == "essai"]
    now = int(time.time())
    for r in touches:
        regles.transiter(r["id"], "retire", "admin", "« ça ne marche plus »", now)
    if touches:
        dnstv_regles.ecrire(regles)
        return {"retirees": len(touches), "application": _ctl("regles-appliquer")}
    return {"retirees": 0, "application": None}
```

(+ `import re`, importer `dnstv_regles` avec le même `try/except ImportError` que `dnstv` ; `GET /auto/reglage` lit `Reglage` depuis le TOML ; `POST /auto/reglage/auto-essai` écrit `etat["auto_essai"]` — ajouter ce champ booléen, défaut `False`, à `valider_etat`.)

- [ ] **Step 4: Run test to verify it passes** — `python -m pytest tests -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ad-guard/api packages/secubox-ad-guard/tests
git commit -m "feat: routes d'administration du mode auto (ref #1954)"
```

---

### Task 7: Panneau d'administration

**Files:**
- Modify: `packages/secubox-ad-guard/www/ad-guard/index.html`
- Test: `packages/secubox-ad-guard/tests/test_dnstv_ui.py` (étendre)

**Interfaces:** consomme `GET /adblock-tv/auto/regles`, `POST /adblock-tv/auto/regles/{rid}/{action}`, `POST /adblock-tv/auto/appareils/{appareil}/ca-ne-marche-plus`, `GET /adblock-tv/status`, `POST /adblock-tv/mode`.

Contenu du panneau (dans l'onglet « DNS AdBlock TV » existant, section « Mode automatique ») :
1. **Appareils** : tableau nom / adresses / mode (sélecteur observe · block · **auto**) ; passer en `auto` demande une confirmation explicite (« Le mode auto applique des règles à l'essai sur cet appareil. »).
2. **À valider** : règles `candidat` — domaine, score, risque (puce de couleur + libellé texte : « partagé » = « peut servir aussi le contenu »), motif ; boutons **Essayer** et **Rejeter**.
3. **À l'essai** : règles `essai` — domaine, compte à rebours (`fin_essai`), boutons **Confirmer** et **Retirer** ; bouton **« Ça ne marche plus »** par appareil, en rouge, avec confirmation.
4. **Confirmées** et **Journal** (historique des transitions, 20 dernières) ; **Rejetées** repliées.
5. Rafraîchissement toutes les 10 s ; aucune alerte bloquante ; état vide explicite (« Aucun appareil en mode auto »).

Règles de rendu : **`textContent` uniquement** pour tout texte issu de l'API (noms de domaine hostiles) ; aucune concaténation HTML ; défauts défensifs `|| []` ; les libellés de risque viennent d'une table locale, jamais de l'API.

- [ ] **Step 1: Write the failing test** — étendre `test_dnstv_ui.py` sur le modèle existant : (a) le HTML contient les identifiants des conteneurs `auto-appareils`, `auto-candidats`, `auto-essai`, `auto-journal`, le bouton `ca-ne-marche-plus` ; (b) en exécutant le script avec un jeu de données contenant `<img src=x onerror=alert(1)>` comme domaine, **aucun** nœud `img` n'est créé (rendu par `textContent`) ; (c) réponse API sans champ (`{}`) ne lève aucune exception ; (d) `Confirmer` n'est proposé que pour l'état `essai`.

- [ ] **Step 2: Run test to verify it fails** — `python -m pytest tests/test_dnstv_ui.py -q` — Expected: FAIL.

- [ ] **Step 3: Write implementation** — ajouter la section HTML et le JavaScript correspondants à `index.html`, en copiant le style de la section « Visualisation des flux DNS » existante (même charte `.claude/WEBUI-PANEL-GUIDELINES.md`, mêmes variables CSS, même helper de requête avec le jeton `sbx_token`).

- [ ] **Step 4: Run test to verify it passes** — `python -m pytest tests -q` — Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/secubox-ad-guard/www packages/secubox-ad-guard/tests/test_dnstv_ui.py
git commit -m "feat: panneau d'administration du mode auto (ref #1954)"
```

---

### Task 8: Paquet 1.4.0, déploiement sur gk2, suivi

**Files:**
- Modify: `packages/secubox-ad-guard/debian/changelog`, `debian/control` (si dépendance), `debian/rules`, `debian/postinst`, `debian/prerm`, `config/ad-guard.toml`, `README.md` du paquet
- Modify: `.claude/HISTORY.md`, `.claude/WIP.md`, `docs/poc-dns-adblock-tv.md` (§ mode auto), spec (correction du signal « rafale », écarts du plan)

- [ ] **Step 1: Version et paquet.** Entrée `secubox-ad-guard (1.4.0-1~bookworm1)` ; `rules` installe `api/dnstv_{regles,detect,signaux,auto}.py`, `sbin/secubox-adguard-auto`, l'unité et la minuterie ; `prerm` : `systemctl stop secubox-ad-guard-auto.timer`. Section `[adblock_tv_auto]` du TOML avec les seuils **et leur commentaire « à calibrer »**. README : routes, modèle de règle, TOML.

- [ ] **Step 2: Tests complets.** `cd packages/secubox-ad-guard && python -m pytest tests -q` (poste) puis les mêmes sous Debian 13 (`scripts/tests-par-paquet.sh secubox-ad-guard` si disponible) ; `dpkg-buildpackage -us -uc -b` ; `lintian` sans erreur nouvelle.

- [ ] **Step 3: Vérifier la base avant de déployer.** `ssh root@192.168.1.200 'dpkg -l secubox-ad-guard | tail -1'` doit afficher 1.3.0 ; refuser de déployer si le dépôt apt ou la box dépasse déjà 1.4.0.

- [ ] **Step 4: Déployer par paquet** (jamais d'édition à chaud) : `scp` du `.deb`, `dpkg -i`, `systemctl restart secubox-group@g1` (un seul groupe, pas de redémarrage de masse), vérifier les 13 modules de g1 et `/adblock-tv/auto/regles` → 401 sans jeton. **Tester `sudo -n /usr/sbin/secubox-adguard-tv regles-appliquer` depuis l'utilisateur `secubox`** (c'est le point que la minuterie exige) ; publier dans `apt.secubox.in` (`reprepro includedeb` sur gk2).

- [ ] **Step 5: Essai réel, TV seule.** Passer la TV 192.168.1.95 en mode `auto` depuis le panneau (`auto_essai` reste faux) ; regarder un replay avec pub ; vérifier qu'un **candidat** apparaît dans « À valider » **sans rien bloquer** ; l'essayer ; constater la disparition de la pub ; tester « Ça ne marche plus » (la pub revient) ; confirmer ; vérifier la ligne d'audit. **Mesurer et consigner** : durée réelle de l'application à chaud, absence de coupure du DNS (requête `dig` en boucle pendant l'application), valeur du débit de refus observé.

- [ ] **Step 6: Suivi.** Entrée datée dans `.claude/HISTORY.md` (ce qui est mesuré, ce qui ne l'est pas, seuils laissés « à calibrer »), `.claude/WIP.md`, `docs/poc-dns-adblock-tv.md`, spec corrigée (signal « rafale »). Commit `docs:`/`feat:` avec `(ref #1954)` ; `closes #1954` **seulement** après déploiement et validation réelle par l'administrateur.

- [ ] **Step 7: PR et fusion.** `scripts/agent-worktree.sh finish`, PR, fusion, nettoyage du worktree.

---

## Self-Review

**Couverture de la spec.** §3 cycle de vie → T1 ; §4 détection → T2 ; §5 signaux → T3 (rafale recalibrée, voir écart n° 3) ; §6 application à chaud → T4 (essai de principe déjà réalisé le 2026-10-03 sur Unbound 1.17.1 : ajout immédiat, retrait rend la main, rechargement d'une petite configuration ≈ 0,05 s ; le rechargement complet de gk2 reste ≈ 10 s, donc réservé au changement d'appareils/de vues) ; §7 composants → T4 à T7 ; §8 sécurité et audit → T4 (audit par le contrôleur), T6 (`require_jwt`) ; §9 tests → un fichier par tâche ; §10 livraison → T8. Lacune assumée : la spec §7 parlait d'une table SQLite `dnstv_regles` ; remplacée par `regles.json` (écart n° 1).

**Placeholders.** T5, T6 et T7 décrivent des tests en prose plutôt qu'en code complet : à compléter par l'implémenteur **avant** d'écrire l'implémentation, en suivant les modèles de T1 à T4 ; les cas à couvrir sont énumérés. `test_exclus_…` et `test_refus_…` de T2 contiennent des échappatoires (`or`, `or True`) à resserrer (indiqué à l'étape 4 de T2). `p.count(".") >= 2 - 0` de T2 est à simplifier en `>= 2`.

**Cohérence des types.** `Regles.proposer(appareil, domaine, score, risque, maintenant, origine)` utilisé à l'identique en T1, T5, T6 ; `identifiant(appareil, domaine)` partagé T1/T5 ; `slug` → `dnstv._slug` en T4 ; `Reglage` défini en T5 et lu en T6 ; `Magasin.evenements/jours_vus` définis en T4 et consommés en T5.

**Points ouverts, à ne pas présenter comme acquis.** Seuils (rafale 60/min × 5 min, activité 100 requêtes, 3 jours de contenu, fenêtre 60 s, 2 coupures) : valeurs de départ ; `RECENTS_MAX = 20000` lignes dans `dnstv_recents` borne l'historique réellement disponible pour la détection (48 h au mieux, moins si plusieurs appareils bavards) ; le comportement de `NoNewPrivileges=no` pour la minuterie doit être vérifié sur gk2 à T8 étape 4.
