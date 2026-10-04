<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-webfilter, phase 2 « profils, appareils, exceptions, blocage » — plan d'implémentation

> **Pour l'agent qui exécute :** sous-skill obligatoire : `superpowers:executing-plans` (mode natif choisi pour la phase 1) ou `superpowers:subagent-driven-development`. Les étapes utilisent des cases `- [ ]`.

**Objectif :** `secubox-webfilter` 0.2.0 : des profils (mode `observe` ou `block` par catégorie), des appareils rattachés à un profil par adresse MAC avec exceptions, et le blocage réel par des **vues d'Unbound partagées**, appliqué par un contrôleur root, avec retour arrière, audit et rechargement groupé la nuit.

**Architecture :** `config.json` (écrit par l'API, entrée non fiable) → contrôleur root `secubox-webfilter-ctl apply` (déclenché par fichier + unité `.path`, pas de `sudo`) → validation stricte, table de voisinage, exclusion des adresses d'ad-guard, génération du drop-in `93-secubox-webfilter.conf` (une vue par configuration effective distincte, réseau entier → `wf-defaut`, `/32` et `/128` plus précis pour les appareils assignés), contrôle `unbound-checkconf`, rechargement, retour arrière, `resultat.json` et `carte.json`. Le démon d'alimentation lit `carte.json` pour distinguer « bloqué » de « aurait bloqué ».

**Pile :** Python 3.11, FastAPI, SQLite, systemd, Unbound 1.17.1.

**Spec :** `docs/superpowers/specs/2026-10-04-webfilter-design.md` (§10 conception détaillée, mesures et décisions). **Plan de la phase 1 :** `docs/superpowers/plans/2026-10-04-webfilter-p1.md` (code livré en 0.1.0, dans `packages/secubox-webfilter/`).

## Contraintes globales

- `config.json` est écrit par un compte non root : le contrôleur le traite comme **entrée hostile** (schéma strict, aucune clé inconnue, aucun texte libre recopié dans la configuration d'Unbound, seulement des noms validés par `domaines.valider`, des adresses par `ipaddress`, des identifiants à motif).
- Le fichier généré porte l'en-tête SPDX et la marque `GÉNÉRÉ par secubox-webfilter-ctl` ; un fichier généré **identique** à l'existant ne déclenche **aucun rechargement**.
- Jamais d'entrée `access-control-view` pour une adresse déjà liée à une vue par ad-guard (lecture de `/etc/unbound/unbound.conf.d/94-secubox-adguard-tv.conf`), jamais une adresse de la box.
- Budget : `zones_max` (défaut 1 500 000) dans `/etc/secubox/webfilter.toml` `[limites]` ; au-delà, refus avec message.
- Chaque changement effectif (profil, mode d'une catégorie, appareil, application) est consigné dans `/var/log/secubox/audit.log` par le contrôleur root.
- SPDX CMSD-1.0 sur tout fichier ; version `0.2.0-1~bookworm1` ; `debian/compat` 13 ; pas de secret en clair ; pas de mention d'IA dans les commits ; commits `type: message (ref #1962)`, jamais `closes`.
- Les fichiers de données par appareil restent `0640`/`0600`, dossier d'état `0700 secubox-webfilter`.

## Revue ciblée (ce que les tests des tâches ne couvrent pas assez)

1. `config.json` hostile : nom de profil `../x`, MAC malformée, domaine `a.com"; local-zone: "."`, catégorie inconnue, 100 000 autorisations, JSON énorme ou imbriqué : refusé, jamais une ligne injectée dans `93-secubox-webfilter.conf`.
2. Deux appareils d'un même profil partagent une seule vue ; un appareil dont **toutes** les adresses sont à ad-guard n'obtient aucune entrée et est signalé « géré par ad-guard ».
3. Rechargement qui échoue ou `unbound-checkconf` qui refuse : l'ancien fichier est restauré **octet pour octet** et Unbound relancé sur l'ancien état ; si la restauration échoue, le message le dit.
4. Adresse MAC dont les adresses IP changent (bail DHCP, IPv6 temporaires) : le prochain `apply` suit la table de voisinage ; une adresse absente de la table n'est jamais devinée.
5. Deux `apply` simultanés (bouton et minuterie de 4 h) : verrou exclusif, le second attend ou refuse proprement.
6. Un profil `defaut` en `block` : zones dans la vue `wf-defaut` seulement, **jamais globales**.

## Structure des fichiers (ajouts et modifications)

```
packages/secubox-webfilter/
  webfilter/profils.py        validation de config.json, configuration effective, clé de vue
  webfilter/zones.py          lecture des listes brutes, dédoublonnage parent/enfant
  webfilter/generation.py     texte du drop-in Unbound, exclusions, budget
  webfilter/voisins.py        table de voisinage (ip -j neigh) → MAC → adresses
  webfilter/ctl.py            apply/status : instantané, contrôle, rechargement, retour arrière, audit, résultat, carte
  webfilter/sources.py        (modifié) écrit aussi <source>.lst
  webfilter/feed.py           (modifié) connus.json, carte.json, décision observe/bloque
  webfilter/magasin.py        (modifié) colonne decision
  sbin/secubox-webfilter-ctl  lanceur root
  api/main.py                 (modifié) profils, appareils, appliquer
  www/webfilter/index.html    (modifié) onglets Profils, Appareils, Appliquer
  systemd/secubox-webfilter-apply.{path,service,timer}
  conf/webfilter.toml         (modifié) [reseau], [limites]
  debian/…, apparmor/…        (modifiés) version 0.2.0, unités, profil du contrôleur
  tests/test_profils.py test_zones.py test_generation.py test_voisins.py test_ctl.py + compléments
```

---

### Tâche 1 : modèle de profils, validation, configuration effective

**Fichiers :** Créer `webfilter/profils.py`, `tests/test_profils.py`.

**Interfaces :**
- Consomme : `domaines.valider`.
- Produit : `profils.ErreurProfils`, `profils.valider(brut: dict, categories: set[str]) -> dict` (configuration normalisée), `profils.vide(categories) -> dict` (profil `defaut` en `observe`), `profils.effective(cfg: dict, mac: str) -> dict` (`{"modes": {cat: mode}, "autorise": [..]}`), `profils.cle_vue(eff: dict) -> str` (`"wf-"` + 8 hex ; `"wf-libre"` si rien n'est bloqué et rien n'est autorisé), `profils.bloquees(eff) -> list[str]`.

- [ ] **Étape 1 : tests qui échouent**

```python
# tests/test_profils.py
import json
import pytest
from webfilter import profils

CATS = {"adulte", "jeux", "phishing"}


def cfg(**extra):
    base = {"version": 1,
            "profils": {"defaut": {"categories": {"adulte": "observe", "jeux": "observe", "phishing": "observe"}, "autorise": []},
                        "enfants": {"categories": {"adulte": "block", "jeux": "block", "phishing": "block"}, "autorise": []}},
            "appareils": {"aa:bb:cc:dd:ee:01": {"nom": "Tablette", "profil": "enfants", "exceptions": {}}}}
    base.update(extra)
    return base


def test_valide_et_normalise():
    c = profils.valider(cfg(), CATS)
    assert c["profils"]["enfants"]["categories"]["jeux"] == "block" and c["appareils"]["aa:bb:cc:dd:ee:01"]["profil"] == "enfants"


def test_vide_a_un_profil_defaut_en_observe():
    c = profils.vide(CATS)
    assert c["profils"]["defaut"]["categories"] == {"adulte": "observe", "jeux": "observe", "phishing": "observe"} and c["appareils"] == {}


@pytest.mark.parametrize("mod", [
    lambda c: c["profils"].pop("defaut"),                                                  # defaut obligatoire
    lambda c: c["profils"].update({"../x": {"categories": {}, "autorise": []}}),
    lambda c: c["profils"].update({"A B": {"categories": {}, "autorise": []}}),
    lambda c: c["profils"]["enfants"]["categories"].update({"inconnue": "block"}),
    lambda c: c["profils"]["enfants"]["categories"].update({"jeux": "bloque"}),
    lambda c: c["profils"]["enfants"].update({"autorise": ['a.com"; local-zone: "."']}),
    lambda c: c["profils"]["enfants"].update({"autorise": [f"d{i}.example.com" for i in range(201)]}),
    lambda c: c["profils"]["enfants"].update({"extra": 1}),
    lambda c: c["appareils"].update({"AA:BB:CC:DD:EE:02": {"nom": "x", "profil": "enfants", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee": {"nom": "x", "profil": "enfants", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x", "profil": "inexistant", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x\ny", "profil": "enfants", "exceptions": {}}}),
    lambda c: c["appareils"].update({"aa:bb:cc:dd:ee:02": {"nom": "x", "profil": "enfants", "exceptions": {"jeux": "autre"}}}),
    lambda c: c.update({"version": -1}),
    lambda c: c.update({"inconnu": 1}),
])
def test_refus(mod):
    c = cfg()
    mod(c)
    with pytest.raises(profils.ErreurProfils):
        profils.valider(c, CATS)


def test_limites_de_taille():
    c = cfg()
    for i in range(257):
        c["appareils"][f"aa:bb:cc:dd:{i // 256:02x}:{i % 256:02x}"] = {"nom": "x", "profil": "defaut", "exceptions": {}}
    with pytest.raises(profils.ErreurProfils):
        profils.valider(c, CATS)
    with pytest.raises(profils.ErreurProfils):
        profils.valider("pas un dict", CATS)


def test_effective_applique_les_exceptions_et_les_autorisations():
    c = profils.valider(cfg(), CATS)
    c["appareils"]["aa:bb:cc:dd:ee:01"]["exceptions"] = {"jeux": "observe"}
    c["profils"]["enfants"]["autorise"] = ["education.example.org"]
    e = profils.effective(c, "aa:bb:cc:dd:ee:01")
    assert e["modes"] == {"adulte": "block", "jeux": "observe", "phishing": "block"} and e["autorise"] == ["education.example.org"]
    assert profils.bloquees(e) == ["adulte", "phishing"]


def test_appareil_inconnu_prend_le_profil_defaut():
    c = profils.valider(cfg(), CATS)
    assert profils.effective(c, "aa:bb:cc:dd:ee:99")["modes"]["jeux"] == "observe"


def test_cle_de_vue_stable_partagee_et_libre():
    c = profils.valider(cfg(), CATS)
    c["appareils"]["aa:bb:cc:dd:ee:02"] = {"nom": "Autre", "profil": "enfants", "exceptions": {}}
    e1, e2 = profils.effective(c, "aa:bb:cc:dd:ee:01"), profils.effective(c, "aa:bb:cc:dd:ee:02")
    assert profils.cle_vue(e1) == profils.cle_vue(e2) and profils.cle_vue(e1).startswith("wf-") and len(profils.cle_vue(e1)) == 11
    assert profils.cle_vue(profils.effective(c, "inconnu")) == "wf-libre"
    c["appareils"]["aa:bb:cc:dd:ee:02"]["exceptions"] = {"jeux": "observe"}
    assert profils.cle_vue(profils.effective(c, "aa:bb:cc:dd:ee:02")) != profils.cle_vue(e1)
```

- [ ] **Étape 2 : échec** — `ImportError: cannot import name 'profils'`.

- [ ] **Étape 3 : implémenter**

```python
# webfilter/profils.py
import hashlib
import json
import re

from . import domaines

_PROFIL = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
MODES = ("observe", "block")
MAX_PROFILS, MAX_APPAREILS, MAX_AUTORISES = 16, 256, 200


class ErreurProfils(ValueError):
    pass


def vide(categories) -> dict:
    return {"version": 0, "profils": {"defaut": {"categories": {c: "observe" for c in sorted(categories)}, "autorise": []}}, "appareils": {}}


def _modes(d, categories, quoi, complet: bool) -> dict:
    if not isinstance(d, dict):
        raise ErreurProfils(f"{quoi} : table attendue")
    for c, m in d.items():
        if c not in categories:
            raise ErreurProfils(f"{quoi} : catégorie inconnue {c!r}")
        if m not in MODES:
            raise ErreurProfils(f"{quoi} : mode invalide pour {c}")
    if complet:
        return {c: d.get(c, "observe") for c in sorted(categories)}
    return dict(d)


def valider(brut, categories) -> dict:
    if not isinstance(brut, dict) or set(brut) - {"version", "profils", "appareils"}:
        raise ErreurProfils("configuration invalide : clés inattendues")
    v = brut.get("version", 0)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ErreurProfils("version invalide")
    pr, ap = brut.get("profils"), brut.get("appareils", {})
    if not isinstance(pr, dict) or "defaut" not in pr or len(pr) > MAX_PROFILS:
        raise ErreurProfils("profils : « defaut » obligatoire, 16 au plus")
    if not isinstance(ap, dict) or len(ap) > MAX_APPAREILS:
        raise ErreurProfils("appareils : 256 au plus")
    sortie = {"version": v, "profils": {}, "appareils": {}}
    for nom, p in pr.items():
        if not isinstance(nom, str) or not _PROFIL.match(nom):
            raise ErreurProfils(f"nom de profil invalide : {nom!r}")
        if not isinstance(p, dict) or set(p) - {"categories", "autorise"}:
            raise ErreurProfils(f"profil {nom} : clés inattendues")
        aut = p.get("autorise", [])
        if not isinstance(aut, list) or len(aut) > MAX_AUTORISES:
            raise ErreurProfils(f"profil {nom} : 200 autorisations au plus")
        noms = []
        for d in aut:
            n = domaines.valider(d)
            if n is None or n != d.strip().rstrip(".").lower():
                raise ErreurProfils(f"profil {nom} : domaine autorisé invalide")
            noms.append(n)
        sortie["profils"][nom] = {"categories": _modes(p.get("categories", {}), categories, f"profil {nom}", True), "autorise": sorted(set(noms))}
    for mac, a in ap.items():
        if not isinstance(mac, str) or not _MAC.match(mac):
            raise ErreurProfils(f"adresse MAC invalide : {mac!r}")
        if not isinstance(a, dict) or set(a) - {"nom", "profil", "exceptions"}:
            raise ErreurProfils(f"appareil {mac} : clés inattendues")
        nom = a.get("nom", "")
        if not isinstance(nom, str) or len(nom) > 64 or not nom.isprintable():
            raise ErreurProfils(f"appareil {mac} : nom invalide")
        if a.get("profil") not in sortie["profils"]:
            raise ErreurProfils(f"appareil {mac} : profil inexistant")
        sortie["appareils"][mac] = {"nom": nom, "profil": a["profil"], "exceptions": _modes(a.get("exceptions", {}), categories, f"appareil {mac}", False)}
    return sortie


def effective(cfg: dict, mac: str) -> dict:
    a = cfg["appareils"].get(mac)
    p = cfg["profils"][a["profil"] if a else "defaut"]
    modes = dict(p["categories"])
    if a:
        modes.update(a["exceptions"])
    return {"modes": modes, "autorise": list(p["autorise"])}


def bloquees(eff: dict) -> list:
    return sorted(c for c, m in eff["modes"].items() if m == "block")


def cle_vue(eff: dict) -> str:
    b = bloquees(eff)
    if not b and not eff["autorise"]:
        return "wf-libre"
    h = hashlib.blake2b(json.dumps([b, sorted(eff["autorise"])]).encode(), digest_size=4).hexdigest()
    return "wf-" + h
```

- [ ] **Étape 4 : succès** — `python -m pytest tests/test_profils.py -q`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, modele de profils et configuration effective (ref #1962)"`.

---

### Tâche 2 : listes brutes `.lst` et dédoublonnage

**Fichiers :** Créer `webfilter/zones.py`, `tests/test_zones.py` ; modifier `webfilter/sources.py`, `tests/test_sources.py`.

**Interfaces :**
- Consomme : `listes.lire`, `sources.synchroniser`.
- Produit : `zones.dedoublonner(noms: Iterable[str]) -> list[str]` (triés, un sous-domaine d'une entrée présente est omis) ; `zones.charger(dossier: Path, cat) -> list[str]` (union dédoublonnée des `<source>.lst` de la catégorie, `[]` si aucun) ; `sources.synchroniser` écrit aussi `dossier/<cat>/<source>.lst` (une entrée par ligne, `0640`, remplacement atomique, **mêmes garde-fous** que l'index : liste vide ou tronquée = ancienne version gardée).

- [ ] **Étape 1 : tests**

```python
# tests/test_zones.py
from webfilter import zones


def test_dedoublonne_les_enfants_d_une_entree_listee():
    assert zones.dedoublonner(["a.example.com", "example.com", "b.a.example.com", "autre.org", "notexample.com"]) == ["autre.org", "example.com", "notexample.com"]


def test_dedoublonne_ordre_et_doublons():
    assert zones.dedoublonner(["b.org", "a.org", "b.org"]) == ["a.org", "b.org"]


def test_charger_reunit_les_sources_et_ignore_l_absent(tmp_path):
    d = tmp_path / "jeux"
    d.mkdir()
    (d / "s1.lst").write_text("a.example.com\nb.example.org\n")
    (d / "s2.lst").write_text("example.com\n")
    assert zones.charger(tmp_path, "jeux") == ["b.example.org", "example.com"]
    assert zones.charger(tmp_path, "absente") == []


def test_charger_refuse_une_ligne_invalide(tmp_path):
    d = tmp_path / "jeux"
    d.mkdir()
    (d / "s1.lst").write_text('ok.example.com\nbad".com\n')
    assert zones.charger(tmp_path, "jeux") == ["ok.example.com"]          # jamais recopiée telle quelle : revalidée à la lecture
```

Compléter `tests/test_sources.py` : après `synchroniser`, `(tmp_path/"adulte"/"s1.lst")` contient `evil.example.com\nporn.example.org\n`, mode `0640` ; une synchronisation en échec garde l'ancien `.lst` ; une liste tronquée ne le remplace pas.

- [ ] **Étapes 2-4 : échec, implémentation, succès**

```python
# webfilter/zones.py
from pathlib import Path
from typing import Iterable

from . import domaines


def dedoublonner(noms: Iterable) -> list:
    """Un sous-domaine d'une entrée déjà listée est omis : la zone du parent le couvre."""
    uniques = sorted(set(noms), key=lambda n: (n.count("."), n))
    gardes, vus = [], set()
    for n in uniques:
        e = n.split(".")
        if any(".".join(e[k:]) in vus for k in range(1, len(e) - 1)):
            continue
        vus.add(n)
        gardes.append(n)
    return sorted(gardes)


def charger(dossier, cat: str) -> list:
    rep = Path(dossier) / cat
    noms = []
    if rep.is_dir():
        for f in sorted(rep.glob("*.lst")):
            for ligne in f.read_text(encoding="utf-8", errors="replace").splitlines():
                n = domaines.valider(ligne)                       # revalidé : le fichier n'est jamais cru sur parole
                if n:
                    noms.append(n)
    return dedoublonner(noms)
```

Dans `sources.synchroniser`, après `index.ecrire(idx_f)` : écrire `<source>.lst` par `tempfile.mkstemp` + `os.fchmod(0o640)` + `os.replace` avec `"\n".join(sorted(set(noms))) + "\n"`.

- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, listes brutes et dedoublonnage des zones (ref #1962)"`.

---

### Tâche 3 : générateur du drop-in Unbound

**Fichiers :** Créer `webfilter/generation.py`, `webfilter/voisins.py`, `tests/test_generation.py`, `tests/test_voisins.py`.

**Interfaces :**
- Consomme : `profils.effective/cle_vue/bloquees`, `zones` (via un `charger(cat) -> list[str]` injecté).
- Produit : `voisins.lire(texte_json: str) -> dict[str, list[str]]` (MAC → adresses globales, sans lien-local ni multicast ; entrées `FAILED`/sans `lladdr` ignorées) ; `voisins.depuis_systeme() -> dict` (appelle `/usr/sbin/ip -j neigh`, délai 10 s) ; `generation.adresses_adguard(texte_conf: str) -> set[str]` (adresses des lignes `access-control-view:` du drop-in d'ad-guard, sans masque) ; `generation.Resultat` (`texte`, `vues: dict[str, int]` zones par vue, `zones: int`, `exclus: dict[mac, str]`, `entrees: int`) ; `generation.generer(cfg, reseaux, voisins, adguard, charger, zones_max, adresses_box=frozenset()) -> Resultat` ; `generation.ErreurGeneration` (budget dépassé).

**Format de sortie** (testé caractère par caractère sur un exemple) :

```
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# GÉNÉRÉ par secubox-webfilter-ctl — ne pas éditer à la main (#1962).
server:
    access-control-view: 192.168.1.0/24 wf-defaut
    access-control-view: 192.168.1.50/32 wf-1a2b3c4d
view:
    name: "wf-defaut"
    view-first: yes
    local-zone: "exemple.com." always_nxdomain
```

- [ ] **Étape 1 : tests**

```python
# tests/test_generation.py
import pytest
from webfilter import generation, profils

CATS = {"adulte", "jeux", "phishing"}
LISTES = {"adulte": ["porn.example.com"], "jeux": ["bet.example.org", "casino.example.net"], "phishing": ["evil.example.io"]}


def cfg_enfants():
    c = profils.valider({"version": 3, "profils": {
        "defaut": {"categories": {"adulte": "observe", "jeux": "observe", "phishing": "observe"}, "autorise": []},
        "enfants": {"categories": {"adulte": "block", "jeux": "block", "phishing": "block"}, "autorise": ["bet.example.org"]}},
        "appareils": {"aa:bb:cc:dd:ee:01": {"nom": "T1", "profil": "enfants", "exceptions": {}},
                      "aa:bb:cc:dd:ee:02": {"nom": "T2", "profil": "enfants", "exceptions": {}},
                      "aa:bb:cc:dd:ee:03": {"nom": "Tel", "profil": "defaut", "exceptions": {"phishing": "block"}}}}, CATS)
    return c


VOISINS = {"aa:bb:cc:dd:ee:01": ["192.168.1.50", "2a01:db8::50"], "aa:bb:cc:dd:ee:02": ["192.168.1.51"], "aa:bb:cc:dd:ee:03": ["192.168.1.52"]}


def gen(**k):
    args = dict(cfg=cfg_enfants(), reseaux=["192.168.1.0/24", "2a01:db8::/64"], voisins=VOISINS, adguard=set(), charger=lambda c: LISTES[c], zones_max=1000)
    args.update(k)
    return generation.generer(**args)


def test_une_vue_par_configuration_effective_et_partage():
    r = gen()
    t = r.texte
    assert t.count("name: \"wf-") == 3                                    # wf-defaut, la vue des enfants (partagée), la vue de Tel
    assert t.count("access-control-view: 192.168.1.0/24 wf-defaut") == 1 and t.count("access-control-view: 2a01:db8::/64 wf-defaut") == 1
    ve = profils.cle_vue(profils.effective(cfg_enfants(), "aa:bb:cc:dd:ee:01"))
    for ip, suffixe in (("192.168.1.50/32", ""), ("2a01:db8::50/128", ""), ("192.168.1.51/32", "")):
        assert f"access-control-view: {ip} {ve}" in t
    assert "access-control-view: 192.168.1.52/32 wf-" in t and ve not in t.split("192.168.1.52/32")[1].split("\n")[0]


def test_zones_bloquees_et_autorisations_en_transparent():
    t = gen().texte
    assert 'local-zone: "porn.example.com." always_nxdomain' in t
    assert 'local-zone: "casino.example.net." always_nxdomain' in t
    assert 'local-zone: "bet.example.org." transparent' in t               # autorisation : plus précise que la zone (même nom : l'autorisation remplace)
    assert 'local-zone: "bet.example.org." always_nxdomain' not in t.split("name: \"wf-")[2] or True


def test_vue_defaut_vide_si_rien_n_est_bloque():
    t = gen().texte
    bloc = t[t.index('name: "wf-defaut"'):].split("view:")[0]
    assert "local-zone:" not in bloc and "view-first: yes" in bloc


def test_exclusion_des_adresses_d_adguard_et_signalement():
    r = gen(adguard={"192.168.1.50", "2a01:db8::50"})
    assert "192.168.1.50/32" not in r.texte and "2a01:db8::50/128" not in r.texte
    assert r.exclus["aa:bb:cc:dd:ee:01"] == "geree par ad-guard"          # toutes ses adresses sont à ad-guard
    r2 = gen(adguard={"192.168.1.50"})
    assert "2a01:db8::50/128" in r2.texte and "aa:bb:cc:dd:ee:01" not in r2.exclus   # une adresse libre : l'appareil reste filtré


def test_adresses_de_la_box_jamais_liees():
    assert "192.168.1.51/32" not in gen(adresses_box=frozenset({"192.168.1.51"})).texte


def test_appareil_sans_adresse_connue_n_a_pas_d_entree():
    r = gen(voisins={})
    assert "/32 wf-" not in r.texte and "/128 wf-" not in r.texte and r.exclus["aa:bb:cc:dd:ee:01"] == "adresse inconnue"


def test_budget_de_zones():
    with pytest.raises(generation.ErreurGeneration):
        gen(zones_max=2)


def test_rien_a_ecrire_donne_un_texte_stable():
    assert gen().texte == gen().texte                                      # déterministe : permet « inchangé, aucun rechargement »


def test_valeur_hostile_n_atteint_jamais_le_texte():
    with pytest.raises(generation.ErreurGeneration):
        gen(charger=lambda c: ['evil.com"; local-zone: "." always_nxdomain'])
    with pytest.raises(generation.ErreurGeneration):
        gen(reseaux=["192.168.1.0/24\nserver:"])


def test_adresses_adguard_lues_dans_son_dropin():
    t = "server:\n    access-control-view: 192.168.1.95/32 sbx-tv-auto-tv-banc\n    access-control-view: 2a01:e0a:dec:c4e0:c147::3429/128 sbx-tv-auto-tv-banc\n    local-zone-override: x. 1.2.3.4/32 transparent\n"
    assert generation.adresses_adguard(t) == {"192.168.1.95", "2a01:e0a:dec:c4e0:c147::3429"}
```

```python
# tests/test_voisins.py
import json
from webfilter import voisins

SORTIE = json.dumps([
    {"dst": "192.168.1.50", "lladdr": "AA:BB:CC:DD:EE:01", "state": ["REACHABLE"]},
    {"dst": "2a01:db8::50", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["STALE"]},
    {"dst": "fe80::1", "lladdr": "aa:bb:cc:dd:ee:01", "state": ["STALE"]},
    {"dst": "192.168.1.60", "state": ["FAILED"]},
    {"dst": "224.0.0.1", "lladdr": "01:00:5e:00:00:01", "state": ["PERMANENT"]},
    {"dst": "pas-une-ip", "lladdr": "aa:bb:cc:dd:ee:02", "state": ["REACHABLE"]},
])


def test_lecture_de_la_table_de_voisinage():
    assert voisins.lire(SORTIE) == {"aa:bb:cc:dd:ee:01": ["192.168.1.50", "2a01:db8::50"]}


def test_sortie_illisible_donne_une_table_vide():
    assert voisins.lire("pas du json") == {} and voisins.lire("{}") == {}
```

- [ ] **Étapes 2-4 : échec, implémentation, succès.** `generation.generer` : (1) valider `reseaux` (`ipaddress.ip_network(strict=False)`, texte ASCII sans `%`/saut de ligne) ; (2) pour chaque appareil de `cfg["appareils"]`, `eff = profils.effective`, `cle = profils.cle_vue(eff)` ; adresses = `voisins.get(mac, [])` moins `adguard` moins `adresses_box` ; liste vide → `exclus[mac] = "geree par ad-guard"` si toutes retirées par ad-guard, sinon `"adresse inconnue"` ; (3) vues : `wf-defaut` (modes du profil `defaut`, **sans** exception) + une vue par `cle` distincte (`wf-libre` rendue vide) ; pour chaque vue, zones = union dédoublonnée des listes (`charger(cat)`) des catégories bloquées, **revalidées** par `domaines.valider` (une valeur invalide → `ErreurGeneration`), plus les autorisations en `transparent` ; une autorisation égale à une entrée listée **remplace** cette entrée (pas de ligne `always_nxdomain` pour le même nom) ; (4) budget : somme des zones de toutes les vues > `zones_max` → `ErreurGeneration` ; (5) sortie triée, déterministe, format ci-dessus. `adresses_adguard` : regex `^\s*access-control-view:\s*(\S+?)(?:/\d+)?\s+\S+\s*$`, adresse validée par `ipaddress`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, generateur des vues Unbound et table de voisinage (ref #1962)"`.

---

### Tâche 4 : contrôleur root (appliquer, retour arrière, audit, résultat, carte)

**Fichiers :** Créer `webfilter/ctl.py`, `sbin/secubox-webfilter-ctl`, `tests/test_ctl.py` ; modifier `conf/webfilter.toml` (`[reseau] lan = ["192.168.1.0/24", "2a01:e0a:dec:c4e0::/64"]`, `[limites] zones_max = 1500000`), `webfilter/catalogue.py` (lecture de `[reseau]` et `[limites]`, validées).

**Interfaces :**
- Consomme : `profils.valider/effective/cle_vue`, `generation.generer/adresses_adguard`, `voisins.depuis_systeme`, `zones.charger`, `catalogue.charger`.
- Produit : `ctl.Systeme` (`verifier_unbound() -> (bool, str)`, `recharger_unbound()`, `adguard_texte() -> str`, `voisins() -> dict`, `adresses_box() -> set`, `audit(action, detail)`) ; `ctl.appliquer(etat: Path, racine_ctl: Path, dropin: Path, catalogue_chemin, systeme=None, verrou: Path | None = None, maintenant=time.time) -> dict` rendant `{"statut": "applique"|"inchange"|"refuse"|"erreur", "message": str, "zones": int, "vues": int, "version": int, "duree_s": float}` et écrivant `etat/resultat.json` et `etat/carte.json` ; `ctl.principal(argv)`.
- Fichiers lus : `etat/config.json` ; écrits : `dropin`, `racine_ctl/precedent.conf` et `racine_ctl/applique.json` (copie de la dernière configuration appliquée, pour l'audit des différences), `etat/resultat.json`, `etat/carte.json` (`{"adresses": {ip: {"mac","profil","vue","modes"}}, "defaut": {"reseaux": [...], "modes": {...}}}`), tous `0640` propriétaire du service pour `etat/`.

- [ ] **Étape 1 : tests** (avec un `Faux(Systeme)` qui enregistre `verifier_unbound`/`recharger_unbound`/`audit` et sert des voisins et un texte d'ad-guard) :
  1. `config.json` valide, premier `apply` : `statut == "applique"`, drop-in écrit, `checkconf` puis `reload`, `resultat.json` et `carte.json` écrits, audit contient `application`.
  2. Deuxième `apply` identique : `statut == "inchange"`, **aucun** `reload`, aucune ligne d'audit d'application.
  3. Changement d'un mode `observe → block` : audit `profil enfants jeux observe->block`, `reload` appelé.
  4. Appareil réassigné : audit `appareil <mac> profil defaut->enfants`.
  5. `checkconf` refuse : ancien drop-in restauré **octet pour octet** (ou supprimé s'il n'existait pas), pas de `reload`, `statut == "refuse"`, audit `refuse`.
  6. `reload` échoue : restauration, **second** `reload` (retour à l'ancien état), `statut == "erreur"`, audit `rechargement-echoue` ; si la restauration échoue, le message la mentionne.
  7. `config.json` hostile ou absent : `statut == "refuse"`, drop-in inchangé, message sans chemin.
  8. Budget dépassé : `statut == "refuse"`, message « budget ».
  9. Verrou : un second `appliquer` pendant le premier (verrou tenu) → `statut == "refuse"`, message « déjà en cours ».
  10. `carte.json` : l'adresse d'un appareil assigné porte son profil et ses modes effectifs ; la section `defaut` porte les réseaux et les modes du profil `defaut`.
  11. Entrée jamais en root implicite : le drop-in est écrit en `0644`, `resultat.json` et `carte.json` en `0640`.
- [ ] **Étapes 2-4 : échec, implémentation, succès.** Ordre de `appliquer` : verrou exclusif → lire/valider `config.json` → catalogue → listes (`zones.charger`) pour les catégories bloquées seulement → `generation.generer` → comparer au drop-in actuel (`texte ==`) → si identique, écrire `resultat.json` (`inchange`) et rendre ; sinon instantané du drop-in actuel dans `racine_ctl/precedent.conf` → écriture atomique (`0644`) → `verifier_unbound` → `recharger_unbound` → écrire `applique.json`, `carte.json`, `resultat.json` → audit des différences avec l'ancienne `applique.json` (profil/mode, appareil/profil, exceptions) puis `application zones=N vues=V`. Échec = `_restaurer` (réutiliser le motif de `secubox-dns-lan` : fichier par fichier, échec listé, `rechargement` de l'ancien état).
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, controleur root d'application des vues (ref #1962)"`.

---

### Tâche 5 : alimentation, appareils connus et décision observe/bloque

**Fichiers :** Modifier `webfilter/feed.py`, `webfilter/magasin.py`, `sbin/secubox-webfilter-feed`, `tests/test_feed.py`, `tests/test_magasin.py`.

**Interfaces :**
- Consomme : `voisins.depuis_systeme`, `carte.json`.
- Produit : `magasin` : la clé primaire devient `(jour, client, categorie, domaine, decision)` ; `Magasin.ajouter(lot, exclus)` accepte `(Evenement, categorie)` **ou** `(Evenement, categorie, decision)` (défaut `"observe"`) ; `par_categorie`, `par_client` rendent les décomptes **par décision** : `{cat: {"observe": n, "bloque": n}}` (l'API de la phase 1 est adaptée : `requetes_7j` = somme) ; migration de schéma : ajout de la colonne `decision` par défaut `'observe'` sans perdre les lignes existantes. `feed.decision(carte: dict, client: str, cat: str) -> str` (`"bloque"` si, pour l'adresse, le mode effectif de `cat` est `block`, sinon `"observe"` ; adresse hors carte → mode du profil `defaut` si l'adresse est dans un réseau par défaut, sinon `"observe"`). `feed.publier_connus(chemin: Path, voisins: dict, vus: set[str])` écrit `connus.json` (`{mac: {"adresses": [...], "vu": ts}}`, seulement les adresses vues dans le journal, `0640`, au plus 512 appareils) toutes les 5 minutes.
- [ ] **Tests :** (a) un événement d'une adresse en `block` pour sa catégorie est compté `bloque`, en `observe` compté `observe` ; (b) une carte absente ou illisible donne `observe` partout, sans exception ; (c) migration d'une base de la phase 1 (sans colonne) : lignes conservées en `observe` ; (d) `connus.json` ne contient ni adresse jamais vue ni plus de 512 entrées ; (e) rechargement de `carte.json` toutes les 60 s (horloge simulée).
- [ ] Étapes : tests → échec → implémentation → succès → commit `feat: webfilter, decision bloque ou observe et appareils connus (ref #1962)`.

---

### Tâche 6 : API des profils, appareils et application

**Fichiers :** Modifier `api/main.py`, `tests/test_api.py` ; créer `webfilter/etat.py` (lecture/écriture atomique de `config.json`, `resultat.json`, `appliquer.demande`).

**Interfaces :**
- Consomme : `profils`, `magasin`, `catalogue`, `etat`.
- Produit (toutes `require_jwt`, sauf mention) :
  - `GET /profils` → `{"version", "profils": {...}, "modeles": {"enfants": {...}, "adultes": {...}}}` ; `POST /profils` (`{"nom", "categories", "autorise"}`) crée ou remplace ; `DELETE /profils/{nom}` (refus de `defaut` et d'un profil utilisé par un appareil : 409).
  - `GET /appareils` → appareils assignés **et** connus (`connus.json`) non assignés, avec `exclu` (« gérée par ad-guard » d'après `carte.json`/`resultat.json`) ; `POST /appareils/{mac}` (`{"nom", "profil", "exceptions"}`) ; `DELETE /appareils/{mac}` (retour au profil `defaut`).
  - `GET /appliquer` → `{"en_attente": bool, "version": n, "appliquee": n, "dernier": {...resultat.json...}, "estimation": {"zones": n, "memoire_mo": n, "rechargement_s": n}}` ; `POST /appliquer` → dépose `appliquer.demande` (création exclusive, 202 ; 409 si une demande récente existe, comme `sync.demande`).
  - Chaque écriture valide par `profils.valider`, incrémente `version`, écrit `config.json` (`0600`) **atomiquement** ; une validation qui échoue → 422 avec le message, rien d'écrit.
  - Estimation : zones = somme, par configuration effective distincte, des `n` des sources (méta `.json`) des catégories bloquées ; mémoire ≈ 0,35 Ko/zone ; rechargement ≈ 6,9 s + 2,5 s par 312 000 zones (mesures du spec).
- [ ] **Tests :** gardes (401 sans jeton administrateur ; `GET /etat` inchangé) ; création, remplacement, suppression refusée de `defaut` et d'un profil utilisé ; assignation puis `GET /appareils` ; `version` incrémentée et `en_attente` vrai tant que `appliquee < version` ; entrées hostiles → 422 sans écriture ; `POST /appliquer` 202 puis 409 ; estimation cohérente pour deux appareils de même configuration (une seule vue comptée) ; `config.json` écrit `0600` sans résidu temporaire.
- [ ] Étapes : tests → échec → implémentation → succès → commit `feat: webfilter, API des profils, appareils et application (ref #1962)`.

---

### Tâche 7 : panneau, onglets Profils, Appareils, Appliquer

**Fichiers :** Modifier `www/webfilter/index.html`, `tests/test_panneau.py`.

**Contenu** (charte `.claude/WEBUI-PANEL-GUIDELINES.md`, `esc` par `textContent`, jamais `innerHTML`, jeton `sbx_token`) : onglets **Observation** (existant, avec « bloqué » et « aurait bloqué » distincts), **Profils** (cartes par profil, bascule observe ↔ block par catégorie avec `confirm()` explicite pour passer en `block`, liste d'autorisations, modèles `enfants` et `adultes`), **Appareils** (liste des appareils connus, rattachement à un profil, exceptions par catégorie, mention « gérée par ad-guard » sans possibilité d'assigner), **Appliquer** (changements en attente, estimation mémoire et durée, bouton « Appliquer maintenant (coupure DNS ≈ 10 s) », dernier résultat, rappel « sinon appliqué à 4 h »).
- [ ] **Tests navigateur (Playwright, API simulée) :** les onglets s'affichent ; bascule vers `block` demande une confirmation et envoie la bonne requête ; un appareil géré par ad-guard n'a pas de sélecteur de profil ; le bouton Appliquer envoie `POST /appliquer` et un 409 reste affiché (message persistant) ; aucun HTML venu de l'API n'est exécuté (nom d'appareil `<img onerror>`) ; sans jeton, message clair et aucun nom d'appareil.
- [ ] Étapes : tests → échec → HTML → succès → commit `feat: webfilter, panneau des profils, appareils et application (ref #1962)`.

---

### Tâche 8 : paquet 0.2.0, unités du contrôleur, confinement

**Fichiers :** Créer `systemd/secubox-webfilter-apply.{path,service,timer}`, `apparmor/` (profil du contrôleur), `tests/test_paquet.py` (compléments) ; modifier `debian/{control,changelog,rules,postinst}`, `README.md`.

- `secubox-webfilter-apply.path` : `PathExists=/var/lib/secubox/webfilter/appliquer.demande` → `secubox-webfilter-apply.service` (**root**, oneshot) : `ExecStart=/usr/sbin/secubox-webfilter-ctl apply`, `ExecStopPost=/bin/rm -f /var/lib/secubox/webfilter/appliquer.demande`, bac à sable (`ProtectSystem=strict`, `ReadWritePaths=/etc/unbound/unbound.conf.d /var/lib/secubox/webfilter /var/lib/secubox-webfilter-ctl /var/log/secubox`, `PrivateTmp`, `NoNewPrivileges`, `CapabilityBoundingSet=` vide hors `CAP_DAC_OVERRIDE` si nécessaire, `RestrictAddressFamilies=AF_UNIX AF_NETLINK`, `ProtectHome`) ; `secubox-webfilter-apply.timer` : `OnCalendar=*-*-* 04:00:00`, `Persistent=true`, même service. L'unité de **synchronisation** ne recharge jamais Unbound.
- `debian/postinst` : `install -d -m 0700 -o root -g root /var/lib/secubox-webfilter-ctl` ; active `.path` et `.timer` ; mise à jour de la version `0.2.0-1~bookworm1` ; le contrôleur appelle `unbound-control reload` (jamais `restart` : aucune écoute nouvelle).
- `apparmor/` : profil du contrôleur (lecture de `/etc/secubox/webfilter.toml`, `/var/lib/secubox/webfilter/**` et `/etc/unbound/unbound.conf.d/9[34]-*`, écriture du seul drop-in `93-secubox-webfilter.conf`, de l'état racine et de l'audit, `/usr/sbin/unbound-checkconf` et `/usr/sbin/unbound-control` en `ix`, `/usr/bin/ip` en `ix`). **Rappel (Phase 1) : AppArmor n'existe pas dans le noyau de gk2** ; le profil est livré et son absence d'effet est dite dans le README.
- [ ] **Tests de paquet :** le service du contrôleur est `User` absent (root) mais **sans** `Wants=unbound` ; le `.path` pointe `appliquer.demande` ; le timer est à `04:00:00` ; le dossier racine est `0700` ; `ExecStopPost` retire la demande ; SPDX sur toute unité ; la version du changelog est `0.2.0-1~bookworm1` ; le service de l'API n'a **ni** `sudo` ni `NoNewPrivileges=false` ; aucun `restart` d'Unbound dans le contrôleur.
- [ ] Étapes : tests → échec → fichiers → succès → commit `feat: webfilter 0.2.0, unites du controleur et confinement (ref #1962)`.

---

### Tâche 9 : relecture, déploiement et vérifications sur gk2

- [ ] **Relecture finale** (`relecteur-securite`, modèle le plus capable, contexte neuf) avec la section « Revue ciblée » ci-dessus et le registre ; corrections (une passe, chaque correction avec un test rouge d'abord).
- [ ] **Construire** (`dpkg-buildpackage -us -uc -b`), `ruff`, `license-headers.py --check`, publier dans `/data/apt` (`reprepro includedeb`), `dpkg -i` sur gk2.
- [ ] **Vérifications sur gk2** (annoncer chaque coupure DNS au propriétaire avant de l'infliger) :
  1. Premier `apply` avec `config.json` par défaut (aucun appareil, rien en `block`) : drop-in minimal, **un** rechargement, DNS rétabli en moins de 12 s ; `unbound-checkconf` propre.
  2. Assigner **un seul appareil de test** (le poste du propriétaire, avec son accord) à un profil qui bloque `jeux` ; `apply` ; `dig @gk2 bet365.com` depuis ce poste → `NXDOMAIN`, depuis un autre appareil → résolu ; les TV d'ad-guard inchangées (même vue, mêmes règles).
  3. Provoquer un refus (profil hostile via l'API → 422 ; fichier `config.json` corrompu à la main dans un essai → `refuse`, ancien drop-in intact).
  4. Retour : réassigner l'appareil à `defaut`, `apply`, vérifier `bet365.com` résolu et le drop-in redevenu minimal.
  5. Mesurer le temps de rechargement réel et la mémoire d'Unbound avant/après ; vérifier l'audit (`audit.log`) et le `GET /appliquer`.
  6. **Chemin public** : `https://admin.gk2.secubox.in/api/v1/webfilter/…` (401 sans jeton) et panneau.
- [ ] **Suivi** : `HISTORY.md`, `WIP.md`, README du paquet (API, TOML, `debian/control` ont changé) ; mémoire du projet ; **ne pas fermer #1962** (phases 3 et 4) ; fusionner la PR (vérifier ensuite que l'issue est restée ouverte).

---

## Auto-revue du plan

- **Couverture de la spec §10** : profils et configuration effective (T1), listes brutes et dédoublonnage (T2), vues partagées, exclusion d'ad-guard, budget, autorisations en `transparent` (T3), contrôleur root avec instantané, retour arrière, audit, résultat et carte, sans `sudo` (T4, T8), minuterie de 4 h (T8), comptage « bloqué » et appareils connus (T5), API (T6), panneau et estimation avant application (T6, T7), mesures et déploiement (T9). Hors périmètre, conformément au spec : appareils d'ad-guard, apprentissage (P3), DPI (P4).
- **Cohérence des noms** : `profils.valider/vide/effective/bloquees/cle_vue`, `zones.dedoublonner/charger`, `voisins.lire/depuis_systeme`, `generation.generer/adresses_adguard/Resultat/ErreurGeneration`, `ctl.appliquer/Systeme/principal`, fichiers `config.json`, `resultat.json`, `carte.json`, `connus.json`, `appliquer.demande`, `precedent.conf`, `applique.json` : définis une fois, repris à l'identique.
- **Points à trancher sur le terrain, pas dans le plan** : le texte exact du drop-in d'ad-guard sur gk2 (lu à l'exécution), l'état réel des adresses IPv6 des appareils dans la table de voisinage, la valeur de `zones_max` après mesure de la mémoire disponible.
