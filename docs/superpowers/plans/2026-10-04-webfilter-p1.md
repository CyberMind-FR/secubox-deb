<!--
  SPDX-License-Identifier: LicenseRef-CMSD-1.0
  Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
  Source-Disclosed License — All rights reserved except as expressly granted.
  See LICENCE-CMSD-1.0.md for terms.
-->

# secubox-webfilter, phase 1 « socle et observe » — plan d'implémentation

> **Pour l'agent qui exécute :** sous-skill obligatoire : `superpowers:subagent-driven-development` (recommandé) ou `superpowers:executing-plans`. Les étapes utilisent des cases `- [ ]`.

**Objectif :** un module `secubox-webfilter` 0.1.0 qui classe, par catégorie (adulte, jeux d'argent, phishing/malware), les requêtes DNS de chaque appareil à partir du journal d'Unbound, en mode **observe** (rien n'est bloqué, aucune zone n'est écrite dans Unbound), avec un panneau d'administration minimal.

**Architecture :** listes publiques téléchargées à l'exécution → **index compact** par catégorie (empreinte de 64 bits par domaine, tableau trié, 8 octets par domaine) → un démon lit le journal d'Unbound, classe chaque nom, compte par jour, appareil, catégorie, domaine (SQLite, 30 jours) → API FastAPI sur socket Unix → panneau. Aucun contrôleur root en P1 : le module ne modifie ni Unbound ni le pare-feu.

**Pile :** Python 3.11 (stdlib : `tomllib`, `sqlite3`, `hashlib`, `array`, `bisect`, `urllib`), FastAPI, pytest, systemd (utilisateur `secubox-webfilter`).

**Spec :** `docs/superpowers/specs/2026-10-04-webfilter-design.md` (§2 listes et résultats de l'essai, §3 objectifs, §4 architecture option B, §5 sécurité, §6 phases).

## Contraintes globales

- Toutes les valeurs externes (noms de domaine des listes et du journal, adresses, URL) sont **validées** avant usage ; jamais recopiées telles quelles dans une configuration, une commande ou un chemin.
- Listes **téléchargées à l'exécution, jamais livrées** dans le paquet ; HTTPS seulement ; taille plafonnée ; échec = on garde la version précédente.
- Données de navigation par appareil : fichiers `0640`, propriétaire `secubox-webfilter`, rétention 30 jours, jamais exportées, lisibles seulement par l'administrateur (`require_jwt` pour tout ce qui détaille un appareil).
- Les requêtes de la box elle-même sont exclues du comptage.
- En-tête SPDX CMSD-1.0 sur tout fichier (`scripts/license-headers.py`). Version `0.1.0-1~bookworm1`, `debian/compat` 13, `Standards-Version: 4.6.2`. Pas de secret en clair. Pas de mention d'IA dans les commits.
- Chaque décision (synchronisation de liste, changement de mode) est tracée dans `/var/log/secubox/audit.log` (ligne JSON `{"ts","module":"webfilter","action","detail"}`, ajout seul).

## Revue ciblée (ce que les tests des tâches ne couvrent pas assez)

1. Liste téléchargée **tronquée, vide ou énorme** : garder l'ancienne, ne jamais remplacer par un index vide.
2. Ligne de journal **hostile ou malformée** (nom énorme, caractères de contrôle, adresse invalide) : ignorée, jamais d'exception qui arrête le démon.
3. Un domaine qui **finit par un nom listé** (`evil.example.com` quand `example.com` est listé) est classé ; `notexample.com` ne l'est pas.
4. **Collision d'empreinte** : 64 bits suffisent pour l'observe (probabilité négligeable) ; un test fixe le comportement documenté.
5. **Course** entre la synchronisation (qui remplace un index) et le démon (qui le lit) : remplacement atomique, relecture sur changement de `mtime`.

## Structure des fichiers

```
packages/secubox-webfilter/
  README.md
  conf/webfilter.toml                  catalogue par défaut (installé en /etc/secubox/webfilter.toml, conffile)
  webfilter/__init__.py
  webfilter/domaines.py                validation d'un nom de domaine
  webfilter/listes.py                  formats de listes, index compact (empreintes triées)
  webfilter/catalogue.py               lecture et validation du TOML
  webfilter/sources.py                 téléchargement borné, construction et remplacement atomique des index
  webfilter/analyse.py                 lignes du journal d'Unbound → événements
  webfilter/magasin.py                 compteurs SQLite, rétention
  webfilter/feed.py                    boucle d'alimentation (testable sans Unbound)
  webfilter/audit.py                   ligne d'audit
  sbin/secubox-webfilter-feed          démon (journal d'Unbound)
  sbin/secubox-webfilter-sync          synchronisation des listes (timer)
  api/main.py                          FastAPI /api/v1/webfilter/*
  www/webfilter/index.html             panneau minimal
  debian/{control,rules,changelog,postinst,prerm,*.service,*.timer}
  apparmor/…                           profil enforce
  tests/…
```

---

### Tâche 1 : validation des noms et lecture des listes

**Fichiers :**
- Créer : `webfilter/__init__.py`, `webfilter/domaines.py`, `webfilter/listes.py`, `tests/conftest.py`, `tests/test_domaines.py`, `tests/test_listes.py`

**Interfaces :**
- Produit : `domaines.valider(brut) -> str | None` (nom normalisé en minuscules sans point final, ou `None`).
- Produit : `listes.lire(texte: str, format: str) -> Iterator[str]` (`format` ∈ `domaines`, `hosts` ; ne rend que des noms valides).
- Produit : `listes.Index` : `Index.depuis(noms: Iterable[str]) -> Index` ; `Index.contient(nom: str) -> bool` (le nom ou l'un de ses parents, à deux étiquettes au moins) ; `len(index)` ; `Index.ecrire(chemin: Path) -> None` (atomique) ; `Index.charger(chemin: Path) -> Index`.

- [ ] **Étape 1 : écrire les tests qui échouent**

```python
# tests/test_domaines.py
import pytest
from webfilter import domaines


@pytest.mark.parametrize("brut,attendu", [
    ("Example.COM", "example.com"), ("example.com.", "example.com"), ("a-b.example.org", "a-b.example.org"),
    ("xn--nxasmq6b.com", "xn--nxasmq6b.com"), ("sub.dom_ain.example.net", "sub.dom_ain.example.net"),
])
def test_valides(brut, attendu):
    assert domaines.valider(brut) == attendu


@pytest.mark.parametrize("brut", [
    "", "localhost", "nodot", "1.2.3.4", "::1", "exa mple.com", "example..com", "-bad.example.com", "bad-.example.com",
    "exa\nmple.com", "exa\x00mple.com", "a" * 64 + ".com", ("a." * 130) + "com", "example.c", "example.123", 'x".com', "é.com", None, 42,
])
def test_refuses(brut):
    assert domaines.valider(brut) is None
```

```python
# tests/test_listes.py
import pytest
from webfilter import listes

HOSTS = "# Title: x\n127.0.0.1 localhost\n0.0.0.0 evil.example.com\n0.0.0.0\tAdult.Example.NET  # note\n!comment\n\n0.0.0.0 bad name.com\n"
DOMAINES = "# c\nevil.example.com\n  PORN.example.org  \n!x\n1.2.3.4\nnodot\n"


def test_lire_hosts():
    assert list(listes.lire(HOSTS, "hosts")) == ["evil.example.com", "adult.example.net"]


def test_lire_domaines():
    assert list(listes.lire(DOMAINES, "domaines")) == ["evil.example.com", "porn.example.org"]


def test_format_inconnu():
    with pytest.raises(ValueError):
        list(listes.lire("x", "xml"))


def test_index_suffixe_et_frontiere():
    i = listes.Index.depuis(["example.com", "sub.other.org"])
    assert i.contient("example.com") and i.contient("evil.example.com") and i.contient("a.b.example.com")
    assert not i.contient("notexample.com") and not i.contient("com") and not i.contient("other.org")
    assert i.contient("x.sub.other.org") and i.contient("sub.other.org")


def test_index_dedoublonne_et_compte():
    assert len(listes.Index.depuis(["a.com", "A.com", "b.com", "a.com"])) == 3


def test_aller_retour_fichier(tmp_path):
    i = listes.Index.depuis(["example.com", "b.org"])
    f = tmp_path / "x.idx"
    i.ecrire(f)
    j = listes.Index.charger(f)
    assert len(j) == 2 and j.contient("www.example.com") and not j.contient("c.net")
    assert oct(f.stat().st_mode & 0o777) == "0o640"
    assert [p.name for p in tmp_path.iterdir()] == ["x.idx"]            # aucun résidu temporaire


def test_charger_refuse_un_fichier_corrompu(tmp_path):
    f = tmp_path / "x.idx"
    f.write_bytes(b"pas un index")
    with pytest.raises(ValueError):
        listes.Index.charger(f)
    f.write_bytes(b"WFIDX1\n" + b"\x00" * 5)                           # longueur non multiple de 8
    with pytest.raises(ValueError):
        listes.Index.charger(f)


def test_index_vide_refuse_a_l_ecriture(tmp_path):
    with pytest.raises(ValueError):
        listes.Index.depuis([]).ecrire(tmp_path / "x.idx")
```

`tests/conftest.py` : `sys.path.insert(0, str(Path(__file__).resolve().parent.parent))` (avec l'en-tête SPDX).

- [ ] **Étape 2 : lancer, constater l'échec**

Run : `cd packages/secubox-webfilter && /home/reepost/CyberMindStudio/secubox-deb/secubox-deb/.venv/bin/python -m pytest tests -q`
Expected : erreur de collecte, `No module named 'webfilter'` (ou `ImportError`).

- [ ] **Étape 3 : implémenter**

```python
# webfilter/domaines.py
import re

_NOM = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$|^(?=.{4,253}$)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+xn--[a-z0-9-]{1,59}$")


def valider(brut) -> str | None:
    """Un nom de domaine DNS (au moins deux étiquettes, TLD alphabétique ou punycode) en minuscules ; None sinon. Jamais d'exception."""
    if not isinstance(brut, str) or not brut.isascii():
        return None
    n = brut.strip().rstrip(".").lower()
    return n if _NOM.match(n) else None
```

```python
# webfilter/listes.py
import array
import bisect
import hashlib
import os
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Iterator

from . import domaines

MAGIE = b"WFIDX1\n"


def lire(texte: str, format: str) -> Iterator[str]:
    if format not in ("domaines", "hosts"):
        raise ValueError(f"format de liste inconnu : {format}")
    for ligne in texte.splitlines():
        ligne = ligne.split("#", 1)[0].strip()
        if not ligne or ligne.startswith("!"):
            continue
        champs = ligne.split()
        if format == "hosts":
            if len(champs) < 2:
                continue
            champ = champs[1]
        else:
            champ = champs[0]
        n = domaines.valider(champ)
        if n:
            yield n


def _h(nom: str) -> int:
    return int.from_bytes(hashlib.blake2b(nom.encode("ascii"), digest_size=8).digest(), "big")


class Index:
    """Domaines listés, réduits à une empreinte de 64 bits : 8 octets par domaine. Une collision (≈ 10⁻¹⁰ pour 4,6 M de domaines) ne
    fait qu'ajouter un faux classement en mode observe ; ce n'est jamais utilisé pour écrire une règle."""

    def __init__(self, empreintes: "array.array"):
        self._a = empreintes

    @classmethod
    def depuis(cls, noms: Iterable[str]) -> "Index":
        return cls(array.array("Q", sorted({_h(n) for n in noms})))

    def __len__(self) -> int:
        return len(self._a)

    def _present(self, nom: str) -> bool:
        h = _h(nom)
        i = bisect.bisect_left(self._a, h)
        return i < len(self._a) and self._a[i] == h

    def contient(self, nom: str) -> bool:
        etiquettes = nom.lower().rstrip(".").split(".")
        for k in range(len(etiquettes) - 1):                      # ne teste jamais le seul TLD
            if self._present(".".join(etiquettes[k:])):
                return True
        return False

    def ecrire(self, chemin: Path) -> None:
        if not len(self._a):
            raise ValueError("index vide : jamais écrit")
        a = array.array("Q", self._a)
        if sys.byteorder == "little":
            a.byteswap()                                          # fichier en grand-boutiste, lisible partout
        fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".idx-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(MAGIE + a.tobytes())
                f.flush()
                os.fchmod(f.fileno(), 0o640)
                os.fsync(f.fileno())
            os.replace(tmp, chemin)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    @classmethod
    def charger(cls, chemin: Path) -> "Index":
        brut = Path(chemin).read_bytes()
        if not brut.startswith(MAGIE) or (len(brut) - len(MAGIE)) % 8:
            raise ValueError(f"{chemin} n'est pas un index valide")
        a = array.array("Q")
        a.frombytes(brut[len(MAGIE):])
        if sys.byteorder == "little":
            a.byteswap()
        return cls(a)
```

- [ ] **Étape 4 : lancer, constater le succès**

Run : `python -m pytest tests -q` — Expected : tous les tests passent.

- [ ] **Étape 5 : commit**

```bash
git add packages/secubox-webfilter && git commit -m "feat: webfilter, validation des noms et index compact des listes (ref #1962)"
```

---

### Tâche 2 : catalogue (TOML validé)

**Fichiers :** Créer `webfilter/catalogue.py`, `conf/webfilter.toml`, `tests/test_catalogue.py`.

**Interfaces :**
- Consomme : rien d'une tâche précédente.
- Produit : `catalogue.Source(nom, url, format, licence, taille_max)`, `catalogue.Categorie(id, libelle, mode, sources: list[Source])`, `catalogue.charger(chemin) -> list[Categorie]`, `catalogue.ErreurCatalogue`.

- [ ] **Étape 1 : tests**

```python
# tests/test_catalogue.py
import pytest
from webfilter import catalogue

BON = '''
[[categorie]]
id = "adulte"
libelle = "Contenu adulte"
mode = "observe"
  [[categorie.source]]
  nom = "hagezi-nsfw"
  url = "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"
  format = "domaines"
  licence = "GPL-3.0"
  taille_max = 5000000
'''


def ecrire(tmp_path, texte):
    p = tmp_path / "w.toml"
    p.write_text(texte)
    return p


def test_charge_le_catalogue(tmp_path):
    cats = catalogue.charger(ecrire(tmp_path, BON))
    assert [c.id for c in cats] == ["adulte"] and cats[0].mode == "observe"
    assert cats[0].sources[0].taille_max == 5_000_000 and cats[0].sources[0].format == "domaines"


@pytest.mark.parametrize("ancien,nouveau", [
    ('id = "adulte"', 'id = "Adulte!"'), ('id = "adulte"', 'id = "../x"'),
    ('mode = "observe"', 'mode = "block"'),                       # le blocage n'existe pas en P1
    ('url = "https://', 'url = "http://'), ('url = "https://', 'url = "file:///'),
    ('format = "domaines"', 'format = "xml"'),
    ("taille_max = 5000000", "taille_max = 900000000"), ("taille_max = 5000000", "taille_max = 0"),
    ('nom = "hagezi-nsfw"', 'nom = "a b"'),
])
def test_valeurs_refusees(tmp_path, ancien, nouveau):
    with pytest.raises(catalogue.ErreurCatalogue):
        catalogue.charger(ecrire(tmp_path, BON.replace(ancien, nouveau)))


def test_doublons_refuses(tmp_path):
    with pytest.raises(catalogue.ErreurCatalogue):
        catalogue.charger(ecrire(tmp_path, BON + BON))


def test_toml_livre_est_valide():
    from pathlib import Path
    cats = catalogue.charger(Path(__file__).resolve().parent.parent / "conf" / "webfilter.toml")
    assert {c.id for c in cats} == {"adulte", "jeux", "phishing"} and all(c.mode == "observe" for c in cats)
```

- [ ] **Étape 2 : constater l'échec** — `ModuleNotFoundError: webfilter.catalogue`.

- [ ] **Étape 3 : implémenter**

```python
# webfilter/catalogue.py
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

TAILLE_MAX_ABSOLUE = 200_000_000
_ID = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_NOM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class ErreurCatalogue(ValueError):
    pass


@dataclass(frozen=True)
class Source:
    nom: str
    url: str
    format: str
    licence: str
    taille_max: int


@dataclass(frozen=True)
class Categorie:
    id: str
    libelle: str
    mode: str
    sources: list


def _txt(d: dict, cle: str, quoi: str, maxi: int = 120) -> str:
    v = d.get(cle)
    if not isinstance(v, str) or not v.strip() or len(v) > maxi or not v.isprintable():
        raise ErreurCatalogue(f"{quoi} : {cle} invalide")
    return v.strip()


def charger(chemin) -> list:
    try:
        brut = tomllib.loads(Path(chemin).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ErreurCatalogue(f"catalogue illisible : {e}") from None
    cats, ids = [], set()
    for c in brut.get("categorie", []):
        cid = _txt(c, "id", "catégorie", 32)
        if not _ID.match(cid) or cid in ids:
            raise ErreurCatalogue(f"catégorie {cid!r} : identifiant invalide ou en double")
        ids.add(cid)
        mode = _txt(c, "mode", cid, 16)
        if mode != "observe":
            raise ErreurCatalogue(f"{cid} : seul le mode « observe » existe dans cette version")
        sources, noms = [], set()
        for s in c.get("source", []):
            nom = _txt(s, "nom", cid, 64)
            if not _NOM.match(nom) or nom in noms:
                raise ErreurCatalogue(f"{cid} : nom de source invalide ou en double")
            noms.add(nom)
            url = _txt(s, "url", nom, 400)
            u = urlsplit(url)
            if u.scheme != "https" or not u.hostname or u.username or u.password:
                raise ErreurCatalogue(f"{nom} : URL https sans identifiants exigée")
            fmt = _txt(s, "format", nom, 16)
            if fmt not in ("domaines", "hosts"):
                raise ErreurCatalogue(f"{nom} : format inconnu")
            taille = s.get("taille_max")
            if not isinstance(taille, int) or isinstance(taille, bool) or not 1 <= taille <= TAILLE_MAX_ABSOLUE:
                raise ErreurCatalogue(f"{nom} : taille_max entre 1 et {TAILLE_MAX_ABSOLUE}")
            sources.append(Source(nom, url, fmt, _txt(s, "licence", nom, 80), taille))
        cats.append(Categorie(cid, _txt(c, "libelle", cid, 80), mode, sources))
    return cats
```

`conf/webfilter.toml` : trois catégories, **sources de la spec §2** :
- `adulte` : `hagezi-nsfw`, `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt`, `domaines`, `GPL-3.0`, `taille_max = 5000000`.
- `jeux` : `hagezi-gambling-medium`, `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.medium-onlydomains.txt`, `domaines`, `GPL-3.0`, `taille_max = 12000000`.
- `phishing` : `blp-phishing`, `https://blocklistproject.github.io/Lists/phishing.txt`, `hosts`, `MIT`, `taille_max = 15000000` ; `urlhaus`, `https://urlhaus.abuse.ch/downloads/hostfile/`, `hosts`, `conditions abuse.ch`, `taille_max = 1000000`.
- Tous en `mode = "observe"` ; en-tête SPDX et commentaire « aucune liste n'est livrée avec le paquet ».

- [ ] **Étape 4 : succès** — `python -m pytest tests -q`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, catalogue de categories valide (ref #1962)"`.

---

### Tâche 3 : synchronisation des listes (téléchargement borné, remplacement atomique)

**Fichiers :** Créer `webfilter/audit.py`, `webfilter/sources.py`, `tests/test_sources.py`.

**Interfaces :**
- Consomme : `catalogue.Source`, `catalogue.Categorie`, `listes.lire`, `listes.Index`.
- Produit : `audit.ecrire(action: str, detail: str = "", chemin: Path | None = None) -> None` ; `sources.telecharger(url: str, taille_max: int) -> bytes` (levée `sources.ErreurSource`) ; `sources.synchroniser(cat, dossier: Path, fetch=telecharger, maintenant=time.time) -> dict` rendant `{source_nom: {"n": int, "ok": bool, "erreur": str|None}}` ; fichiers `dossier/<cat.id>/<source.nom>.idx` et `dossier/<cat.id>/<source.nom>.json` (méta : `n`, `ts`, `sha256`, `licence`, `url`).

- [ ] **Étape 1 : tests**

```python
# tests/test_sources.py
import hashlib
import json
import pytest
from webfilter import catalogue, listes, sources

CAT = catalogue.Categorie("adulte", "Adulte", "observe", [catalogue.Source("s1", "https://x.example/l.txt", "domaines", "MIT", 1000)])
LISTE = "evil.example.com\nporn.example.org\n"


def fetch_ok(url, taille_max):
    return LISTE.encode()


def test_synchronise_ecrit_index_et_meta(tmp_path):
    r = sources.synchroniser(CAT, tmp_path, fetch=fetch_ok, maintenant=lambda: 1000)
    assert r["s1"] == {"n": 2, "ok": True, "erreur": None}
    idx = listes.Index.charger(tmp_path / "adulte" / "s1.idx")
    assert idx.contient("a.evil.example.com")
    meta = json.loads((tmp_path / "adulte" / "s1.json").read_text())
    assert meta["n"] == 2 and meta["ts"] == 1000 and meta["sha256"] == hashlib.sha256(LISTE.encode()).hexdigest() and meta["licence"] == "MIT"


def test_echec_garde_l_ancienne_version(tmp_path):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    def boum(url, taille_max):
        raise sources.ErreurSource("réseau coupé")
    r = sources.synchroniser(CAT, tmp_path, fetch=boum)
    assert r["s1"]["ok"] is False and "réseau" in r["s1"]["erreur"]
    assert listes.Index.charger(tmp_path / "adulte" / "s1.idx").contient("evil.example.com")


@pytest.mark.parametrize("corps", [b"", b"# que des commentaires\n", b"nodot\n1.2.3.4\n"])
def test_liste_vide_ou_sans_domaine_valide_ne_remplace_rien(tmp_path, corps):
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    r = sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: corps)
    assert r["s1"]["ok"] is False
    assert listes.Index.charger(tmp_path / "adulte" / "s1.idx").contient("evil.example.com")


def test_liste_qui_perd_plus_de_la_moitie_est_refusee(tmp_path):
    gros = "\n".join(f"d{i}.example.com" for i in range(100)).encode()
    sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: gros)
    r = sources.synchroniser(CAT, tmp_path, fetch=lambda u, m: b"seul.example.com\n")        # 100 → 1 : liste tronquée
    assert r["s1"]["ok"] is False and "tronqu" in r["s1"]["erreur"]


def test_telecharger_refuse_http_et_depassement(monkeypatch):
    with pytest.raises(sources.ErreurSource):
        sources.telecharger("http://x.example/l.txt", 100)
    class Rep:
        def __init__(self, n): self.n = n; self.headers = {}
        def read(self, k=-1): d = b"a" * min(self.n, k if k > 0 else self.n); self.n -= len(d); return d
        def __enter__(self): return self
        def __exit__(self, *a): return False
        status = 200
    monkeypatch.setattr(sources, "_ouvrir", lambda url: Rep(5000))
    with pytest.raises(sources.ErreurSource):
        sources.telecharger("https://x.example/l.txt", 1000)
    monkeypatch.setattr(sources, "_ouvrir", lambda url: Rep(500))
    assert len(sources.telecharger("https://x.example/l.txt", 1000)) == 500


def test_audit_a_chaque_synchronisation(tmp_path, monkeypatch):
    vus = []
    monkeypatch.setattr(sources.audit, "ecrire", lambda a, d="", chemin=None: vus.append((a, d)))
    sources.synchroniser(CAT, tmp_path, fetch=fetch_ok)
    assert vus and vus[0][0] == "sync" and "adulte/s1" in vus[0][1] and "n=2" in vus[0][1]
```

- [ ] **Étape 2 : échec** — `ModuleNotFoundError: webfilter.sources`.

- [ ] **Étape 3 : implémenter**

```python
# webfilter/audit.py
import json
import sys
import time
from pathlib import Path

AUDIT = Path("/var/log/secubox/audit.log")


def ecrire(action: str, detail: str = "", chemin: Path | None = None) -> None:
    try:
        with open(chemin or AUDIT, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "webfilter",
                                "action": action, "detail": detail[:300]}, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"secubox-webfilter : audit non écrit ({action}) : {e}", file=sys.stderr)
```

```python
# webfilter/sources.py
import hashlib
import json
import os
import tempfile
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import audit, listes

DELAI_S = 60
FRACTION_MIN = 0.5                    # une liste qui perd plus de la moitié de ses entrées est jugée tronquée


class ErreurSource(RuntimeError):
    pass


class _SansRedirectionHttp(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise ErreurSource("redirection hors https refusée")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _ouvrir(url: str):
    return urllib.request.build_opener(_SansRedirectionHttp).open(
        urllib.request.Request(url, headers={"User-Agent": "secubox-webfilter/0.1"}), timeout=DELAI_S)


def telecharger(url: str, taille_max: int) -> bytes:
    if urlsplit(url).scheme != "https":
        raise ErreurSource("https exigé")
    try:
        with _ouvrir(url) as r:
            if getattr(r, "status", 200) != 200:
                raise ErreurSource(f"réponse {r.status}")
            morceaux, total = [], 0
            while True:
                m = r.read(65536)
                if not m:
                    break
                total += len(m)
                if total > taille_max:
                    raise ErreurSource(f"plus de {taille_max} octets : refusé")
                morceaux.append(m)
    except ErreurSource:
        raise
    except Exception as e:                                           # réseau, TLS, délai : jamais une exception brute
        raise ErreurSource(f"téléchargement impossible : {type(e).__name__}") from None
    return b"".join(morceaux)


def _ecrire_meta(chemin: Path, meta: dict) -> None:
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".meta-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(meta, f)
        os.fchmod(f.fileno(), 0o640)
    os.replace(tmp, chemin)


def synchroniser(cat, dossier: Path, fetch=telecharger, maintenant=time.time) -> dict:
    sortie = {}
    rep = Path(dossier) / cat.id
    rep.mkdir(parents=True, exist_ok=True)
    for s in cat.sources:
        idx_f, meta_f = rep / f"{s.nom}.idx", rep / f"{s.nom}.json"
        try:
            brut = fetch(s.url, s.taille_max)
            noms = list(listes.lire(brut.decode("utf-8", "replace"), s.format))
            if not noms:
                raise ErreurSource("aucun domaine valide : liste vide ou format inattendu")
            index = listes.Index.depuis(noms)
            if idx_f.exists():
                ancien = len(listes.Index.charger(idx_f))
                if len(index) < ancien * FRACTION_MIN:
                    raise ErreurSource(f"liste tronquée ({len(index)} contre {ancien}) : ancienne version gardée")
            index.ecrire(idx_f)
            _ecrire_meta(meta_f, {"n": len(index), "ts": int(maintenant()), "sha256": hashlib.sha256(brut).hexdigest(),
                                  "licence": s.licence, "url": s.url})
            sortie[s.nom] = {"n": len(index), "ok": True, "erreur": None}
            audit.ecrire("sync", f"{cat.id}/{s.nom} n={len(index)}")
        except (ErreurSource, ValueError, OSError) as e:
            sortie[s.nom] = {"n": 0, "ok": False, "erreur": str(e)[:160]}
            audit.ecrire("sync-echec", f"{cat.id}/{s.nom} {e}"[:290])
    return sortie
```

- [ ] **Étape 4 : succès** — `python -m pytest tests -q`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, synchronisation bornee des listes (ref #1962)"`.

---

### Tâche 4 : analyse du journal d'Unbound et comptage

**Fichiers :** Créer `webfilter/analyse.py`, `webfilter/magasin.py`, `tests/test_analyse.py`, `tests/test_magasin.py`.

**Interfaces :**
- Consomme : `domaines.valider`, `listes.Index`.
- Produit : `analyse.Evenement(ts: int, client: str, qname: str, qtype: str, rcode: str)` ; `analyse.ligne(texte: str) -> Evenement | None` (lignes `reply:` d'Unbound, types A, AAAA, HTTPS seulement ; client IP validée ; `qname` validé) ; `analyse.classer(qname, indexes: dict[str, Index]) -> str | None` (identifiant de la première catégorie qui contient le nom).
- Produit : `magasin.Magasin(chemin)` avec `ajouter(lot: Iterable[tuple[Evenement, str]], exclus: set[str]) -> int`, `par_categorie(depuis_jour: str) -> dict[str, int]`, `par_client(depuis_jour: str) -> dict[str, dict[str, int]]`, `top_domaines(categorie: str, depuis_jour: str, n: int = 50) -> list[tuple[str, int]]`, `purger(retention_jours: int, maintenant: int | None = None) -> int`. Table `wf_counts(jour, client, categorie, domaine, n)` ; fichier `0640`.

- [ ] **Étape 1 : tests** (extraits décisifs, à compléter dans le même style)

```python
# tests/test_analyse.py
from webfilter import analyse, listes

L = "[1791090000] unbound[1234:0] reply: 192.168.1.95 evil.example.com. A IN NOERROR 0.000000 0 60"


def test_ligne_reply_valide():
    e = analyse.ligne(L)
    assert (e.ts, e.client, e.qname, e.qtype, e.rcode) == (1791090000, "192.168.1.95", "evil.example.com", "A", "NOERROR")


def test_types_ignores_et_lignes_etrangeres():
    assert analyse.ligne(L.replace(" A IN", " MX IN")) is None
    assert analyse.ligne(L.replace("reply:", "query:")) is None
    assert analyse.ligne("n'importe quoi") is None and analyse.ligne("") is None


def test_valeurs_hostiles_ignorees():
    assert analyse.ligne(L.replace("192.168.1.95", "pas-une-ip")) is None
    assert analyse.ligne(L.replace("evil.example.com.", "x" * 300 + ".com.")) is None
    assert analyse.ligne(L.replace("evil.example.com.", "bad name.com.")) is None
    assert analyse.ligne(L.replace("192.168.1.95", "fe80::1%eth0")) is None


def test_ipv6_acceptee():
    assert analyse.ligne(L.replace("192.168.1.95", "2a01:e0a:dec:c4e0::200")).client == "2a01:e0a:dec:c4e0::200"


def test_classer_premiere_categorie_en_ordre():
    idx = {"adulte": listes.Index.depuis(["example.com"]), "jeux": listes.Index.depuis(["example.com", "bet.example.org"])}
    assert analyse.classer("x.example.com", idx) == "adulte"
    assert analyse.classer("bet.example.org", idx) == "jeux"
    assert analyse.classer("sain.example.net", idx) is None
```

```python
# tests/test_magasin.py
from webfilter import analyse, magasin


def ev(ts, client, nom):
    return analyse.Evenement(ts, client, nom, "A", "NOERROR")


def test_comptage_et_exclusion(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    n = m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte"), (ev(1791090001, "192.168.1.95", "a.example.com"), "adulte"),
                   (ev(1791090002, "192.168.1.200", "a.example.com"), "adulte"), (ev(1791090003, "192.168.1.5", "bet.example.org"), "jeux")],
                  exclus={"192.168.1.200"})
    assert n == 3
    assert m.par_categorie("2026-10-01") == {"adulte": 2, "jeux": 1}
    assert m.par_client("2026-10-01")["192.168.1.95"] == {"adulte": 2}
    assert m.top_domaines("adulte", "2026-10-01") == [("a.example.com", 2)]


def test_retention_et_droits(tmp_path):
    m = magasin.Magasin(tmp_path / "w.db")
    m.ajouter([(ev(1791090000, "192.168.1.95", "a.example.com"), "adulte")], exclus=set())
    assert m.purger(30, maintenant=1791090000 + 31 * 86400) == 1 and m.par_categorie("2020-01-01") == {}
    assert oct((tmp_path / "w.db").stat().st_mode & 0o777) == "0o640"
```

- [ ] **Étape 2 : échec** — modules absents.

- [ ] **Étape 3 : implémenter** `analyse.py` (regex `^\[(\d+)\] unbound\[\d+:\d+\] reply: (\S+) (\S+) (A|AAAA|HTTPS) IN (\w+)`, `ipaddress.ip_address` strict sans `%`, `domaines.valider(qname)`) et `magasin.py` (SQLite WAL, `INSERT … ON CONFLICT DO UPDATE SET n = n + excluded.n`, jour UTC `AAAA-MM-JJ`, `os.chmod(chemin, 0o640)` à la création, `purger` supprime `jour < seuil`).
- [ ] **Étape 4 : succès** — `python -m pytest tests -q`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, analyse du journal d'Unbound et comptage (ref #1962)"`.

---

### Tâche 5 : boucle d'alimentation et démon

**Fichiers :** Créer `webfilter/feed.py`, `sbin/secubox-webfilter-feed`, `sbin/secubox-webfilter-sync`, `tests/test_feed.py`.

**Interfaces :**
- Consomme : `analyse.ligne`, `analyse.classer`, `magasin.Magasin.ajouter`, `catalogue.charger`, `listes.Index.charger`.
- Produit : `feed.charger_indexes(dossier: Path, categories) -> dict[str, Index]` (réunit les index de chaque source d'une catégorie ; un index illisible est ignoré et signalé sur stderr) ; `feed.suivre(lignes, magasin, indexes_fn, exclus_fn, periode_s=2.0, lot=200) -> int` (rend le nombre d'événements classés enregistrés ; `indexes_fn()` est rappelée toutes les 60 s ou quand `mtime` change).

- [ ] **Étape 1 : tests** — (a) 3 lignes dont 2 d'un nom listé et 1 d'un nom sain, plus 1 de la box : `suivre` rend 2 ; (b) une ligne hostile entre deux bonnes n'interrompt pas la boucle ; (c) un index remplacé pendant la boucle (nouvelle empreinte, même chemin) est pris en compte à l'appel suivant d'`indexes_fn` ; (d) `charger_indexes` ignore un `.idx` corrompu sans lever.
- [ ] **Étape 2 : échec** — module absent.
- [ ] **Étape 3 : implémenter** ; `secubox-webfilter-feed` suit `journalctl -u unbound -f -o cat` (sinon `--stdin` pour les essais), exclut les adresses locales de la box (lecture de `ip -j addr`, comme le démon d'ad-guard), purge la rétention toutes les heures ; `secubox-webfilter-sync` charge `/etc/secubox/webfilter.toml`, appelle `sources.synchroniser` pour chaque catégorie et rend un code de sortie non nul si **toutes** les sources d'une catégorie ont échoué.
- [ ] **Étape 4 : succès** — `python -m pytest tests -q`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, demon d'alimentation et synchronisation (ref #1962)"`.

---

### Tâche 6 : API

**Fichiers :** Créer `api/main.py`, `tests/test_api.py`.

**Interfaces :**
- Consomme : `catalogue`, `magasin`, `sources`, `secubox_core.auth` (`require_lecture`, `require_jwt`) ; **à imiter** : la structure de `packages/secubox-ad-guard/api/main.py` (import relatif avec repli, `app`, routeur monté, socket `/run/secubox/webfilter.sock`), conforme à la mémoire « l'agrégateur sert les modules en processus ».
- Produit : `GET /api/v1/webfilter/etat` (`require_lecture`) → catégories, mode, sources (nom, `n`, `ts`, licence, attribution) ; `GET /api/v1/webfilter/stats?jours=7` (`require_jwt` : détail par appareil) → `{"par_categorie": …, "par_client": …}` ; `GET /api/v1/webfilter/categories/{id}/domaines?jours=7&n=50` (`require_jwt`) ; `POST /api/v1/webfilter/sync` (`require_jwt`, tâche de fond, répond tout de suite 202).

- [ ] **Étape 1 : tests** — état lisible avec `require_lecture` seulement (sans nom d'appareil) ; `stats` et `domaines` refusés sans jeton administrateur (401/403) ; `jours` hors de 1–30 → 422 ; `id` de catégorie inconnu → 404 ; `POST /sync` répond 202 et appelle `sources.synchroniser` (substitué) ; aucune route n'expose un chemin de fichier ni une adresse hors de ce qui est listé.
- [ ] **Étape 2 : échec** — `api/main.py` absent.
- [ ] **Étape 3 : implémenter** (modèles Pydantic, `Query(ge=1, le=30)`, `HTTPException(404)` pour une catégorie inconnue).
- [ ] **Étape 4 : succès** — `python -m pytest tests -q`.
- [ ] **Étape 5 : commit** — `git commit -m "feat: webfilter, API d'observation (ref #1962)"`.

---

### Tâche 7 : panneau d'administration minimal

**Fichiers :** Créer `www/webfilter/index.html`, `tests/test_panneau.py`.

**Contenu et contraintes** (`.claude/WEBUI-PANEL-GUIDELINES.md`, `.claude/DESIGN-CHARTER.md`, jeton `sbx_token`) : une carte par catégorie (mode « observe », nombre de domaines listés, date de la dernière synchronisation, licence et attribution de chaque source) ; un tableau « aurait été bloqué » par catégorie et par appareil sur 7 jours ; un bouton « Synchroniser les listes » ; un avertissement permanent « mode observe : rien n'est bloqué » et la mention des limites (DoH, VPN, IP directe). Aucun JS ni CSS porté de LuCI à modifier. **Tests** (banc navigateur comme pour ad-guard, Playwright) : le panneau s'affiche avec des données simulées, affiche un tiret quand une valeur manque, refuse d'afficher un nom d'appareil sans jeton (message clair), n'exécute aucun HTML venu de l'API (injection d'un nom `<img onerror>` : texte brut).
- [ ] Étapes : tests → échec → HTML → succès → commit `feat: webfilter, panneau d'observation (ref #1962)`.

---

### Tâche 8 : paquet, services, confinement, déploiement

**Fichiers :** Créer `debian/*`, `apparmor/*`, `README.md`, entrée de menu `menu.d/`, route WAF `secubox-waf-route`.

- `debian/control` : `Architecture: all`, `Depends: ${misc:Depends}, python3 (>= 3.11), secubox-core (>= 1.4.0), python3-fastapi | python3-pip`, `Rules-Requires-Root: no`, `Standards-Version: 4.6.2`, `debhelper-compat (= 13)`.
- Unités : `secubox-webfilter.service` (API, `User=secubox-webfilter`, socket Unix `/run/secubox/webfilter.sock`, `ExecStartPre=+/bin/rm -f` de la socket périmée — leçon `project_run_secubox_socket_sticky_unlink`), `secubox-webfilter-feed.service` (suit le journal ; `SupplementaryGroups=systemd-journal` ; **pas** d'option seccomp qui implique `NoNewPrivileges` si un `sudo` est un jour requis, sans objet en P1), `secubox-webfilter-sync.service` + `.timer` (toutes les 6 h, `Persistent=true`). `ReadWritePaths=/var/lib/secubox-webfilter /var/log/secubox`.
- `postinst` : crée l'utilisateur système, `/var/lib/secubox-webfilter` (`0750`), `systemctl enable --now` du démon et du timer, première synchronisation en arrière-plan ; `prerm` : `systemctl stop`.
- AppArmor **enforce** (lecture du journal et de `/etc/secubox/webfilter.toml`, écriture dans le dossier d'état et l'audit).
- Déploiement : construire, publier dans `/data/apt` (`reprepro includedeb`), `dpkg -i` sur gk2, **redémarrer l'agrégateur** (il sert les modules en processus, ≈ 30–50 s), vérifier **par l'adresse publique** et non par le socket du module, vérifier qu'Unbound n'a **ni rechargé ni redémarré** (même PID), consigner dans l'issue, `HISTORY.md`, `WIP.md`, `MIGRATION-MAP.md` ; ne **pas** fermer #1962 (phases 2 à 4).
- **Relecture de sécurité** (`relecteur-securite`) avant le déploiement ; corriger les constats bloquants et importants avec un test rouge d'abord.
- [ ] Étapes : écrire, construire (`dpkg-buildpackage -us -uc -b`), `ruff`, `license-headers.py --check`, relecture, déployer, vérifier, consigner, fusionner.

---

## Auto-revue du plan

- **Couverture de la spec P1** : catalogue (T2), listes publiques bornées (T3), observe sans zone écrite (T4–T5), comptage par appareil et rétention 30 jours (T4), panneau minimal (T7), API (T6), audit (T3, T8), vie privée et droits (T4, T6, T8). Hors P1, volontairement : profils, appareils par MAC, exceptions, blocage, apprentissage, association au DPI (P2 à P4).
- **Cohérence des noms** : `Index.depuis/contient/ecrire/charger`, `listes.lire`, `analyse.ligne/classer/Evenement`, `Magasin.ajouter/par_categorie/par_client/top_domaines/purger`, `sources.synchroniser/telecharger`, `catalogue.charger` sont définis une fois et réutilisés à l'identique.
- **Points d'exécution à trancher sur le terrain, pas dans le plan** : le format exact des lignes `reply:` du journal de gk2 (vérifié ce jour : `reply: <client> <nom>. <type> IN <rcode> <durée>`), l'obtention des adresses locales de la box, et la route WAF du module.
