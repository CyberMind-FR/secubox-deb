# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Catalogue des catégories et de leurs sources de listes (/etc/secubox/webfilter.toml), validé : rien d'inconnu n'en sort."""
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
