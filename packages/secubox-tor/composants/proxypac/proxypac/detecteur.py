# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: proxypac.detecteur — candidats CDN, alimentés en silence (#2752, cf. #743).

Lit en LECTURE SEULE le magasin DNS d'ad-guard (dnstv_counts : ce que les appareils ont réellement demandé), reconnaît les hôtes de CDN par un
catalogue EXPLICITE (jamais un « ressemble à »), et dépose candidates.json. Rien n'est activé : accepter ou rejeter reste à l'opérateur. Un hôte
déjà réglé (rules.d) ou rejeté n'est plus proposé. Un magasin illisible laisse les candidats en place."""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Optional

# famille -> domaines ENREGISTRÉS : l'hôte doit EN être un sous-domaine exact (un point devant), pas une simple fin de chaîne.
CATALOGUE = {
    "google": ("googleapis.com", "gstatic.com", "googleusercontent.com", "ggpht.com"),
    "cloudflare": ("cdnjs.cloudflare.com",),
    "jsdelivr": ("cdn.jsdelivr.net", "jsdelivr.net"),
    "unpkg": ("unpkg.com",),
    "cloudfront": ("cloudfront.net",),
    "jquery": ("code.jquery.com",),
    "bootstrap": ("maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com"),
    "microsoft": ("ajax.aspnetcdn.com",),
}
_HOTE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _normal(hote: str) -> str:
    return (hote or "").strip().lower().rstrip(".")


def famille(hote: str) -> Optional[str]:
    h = _normal(hote)
    if not _HOTE.match(h):
        return None
    for nom, domaines in CATALOGUE.items():
        for d in domaines:
            if h == d or h.endswith("." + d):
                return nom
    return None


def _couvert(hote: str, regles: set) -> bool:
    return any(hote == r or ("*" in r and fnmatch.fnmatchcase(hote, r)) for r in regles)


def detecter(db: Path, jours: int, regles: set, rejetes: set, limite: int = 200) -> Optional[list]:
    """Candidats CDN vus depuis `jours` jours, les plus demandés d'abord ; None si le magasin est illisible."""
    depuis = time.strftime("%Y-%m-%d", time.gmtime(time.time() - jours * 86400))
    try:
        if not Path(db).is_file():
            return None
        con = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=5)
        try:
            lignes = con.execute("SELECT domaine, client, jour, hits FROM dnstv_counts WHERE jour >= ? AND decision = 'ALLOWED'", (depuis,)).fetchall()
        finally:
            con.close()
    except (sqlite3.Error, OSError):
        return None
    agreg: dict = {}
    for domaine, client, jour, hits in lignes:
        h = _normal(domaine)
        fam = famille(h)
        if not fam or h in rejetes or _couvert(h, regles):
            continue
        a = agreg.setdefault(h, {"host": h, "hits": 0, "_c": set(), "derniere_vue": "", "famille": fam, "source": "dns"})
        a["hits"] += int(hits or 0)
        a["_c"].add(client)
        a["derniere_vue"] = max(a["derniere_vue"], jour)
    out = []
    for a in agreg.values():
        a["clients"] = len(a.pop("_c"))
        out.append(a)
    out.sort(key=lambda x: (-x["hits"], x["host"]))
    return out[:limite]


def _lire_liste(p: Path) -> set:
    try:
        v = json.loads(Path(p).read_text())
        return {_normal(x) for x in v if isinstance(x, str)} if isinstance(v, list) else set()
    except (OSError, ValueError):
        return set()


def _hotes_regles(rules_dir: Path) -> set:
    hotes = set()
    try:
        for f in sorted(Path(rules_dir).glob("*.rules")):
            for ligne in f.read_text().splitlines():
                ligne = ligne.strip()
                if ligne and not ligne.startswith("#"):
                    hotes.add(_normal(ligne.split()[0]))
    except OSError:
        pass
    return hotes


def passe(db: Path, sortie: Path, rules_dir: Path, rejetes_json: Path, jours: int = 7) -> int:
    """Un passage : écrit `sortie` (atomique) ; un magasin illisible ne touche à rien. Rend toujours 0 (n'échoue pas une minuterie)."""
    c = detecter(db, jours, _hotes_regles(rules_dir), _lire_liste(rejetes_json))
    if c is None:
        return 0
    sortie = Path(sortie)
    sortie.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=sortie.parent, prefix=".candidates-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(c, f, ensure_ascii=False, indent=1)
        os.chmod(tmp, 0o644)
        os.replace(tmp, sortie)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return 0
