# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Téléchargement borné des listes publiques et remplacement atomique des index : un échec garde toujours la version précédente."""
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
