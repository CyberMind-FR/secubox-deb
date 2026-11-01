# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Référence évolutive de l'activité habituelle d'une box (LED de supervision, ref #3361).

Pour chaque mesure (clé), deux références s'additionnent :
  - la longue : moyenne et dispersion EWMA (demi-vie 7 j) par tranche horaire de la
    semaine (168 tranches, heure locale, lundi 0 h = 0) ;
  - la courte : moyenne et dispersion EWMA (demi-vie 1 h), toutes tranches confondues.

Le niveau (0..3) est le plus haut des deux : z = (valeur - moyenne) / max(dispersion,
plancher), puis z < 1 -> 0, < 2 -> 1, < 3 -> 2, sinon 3. Pendant les 24 premières
heures d'observation d'une clé, le niveau est plafonné à 1 (apprentissage).

Choix de conception : une tranche n'est visitée qu'une heure par semaine. La référence
longue y est donc mise à jour **par visite** (au changement d'heure), avec le poids
alpha = 1 - 2^(-écart entre deux visites / demi-vie), et non échantillon par échantillon.
Ainsi une attaque d'une heure ne contamine pas la référence qui sert à la juger, et une
hausse durable devient normale en quelques semaines.

Aucune lecture de l'horloge : le temps (epoch, secondes) est toujours passé par l'appelant.
Tout dict de persistance invalide donne une référence vide (retour en apprentissage).
"""
import math
import time

VERSION = 1
DELTA_MAX_COURT = 3600.0         # borne de l'écart entre deux relevés (saut d'horloge, arrêt)
ECART_MAX_VISITES = 14 * 86400.0  # borne de l'écart entre deux visites d'une même tranche


def tranche(t):
    """Tranche horaire de la semaine en heure locale : lundi 0 h = 0 ... dimanche 23 h = 167."""
    lt = time.localtime(t)
    return lt.tm_wday * 24 + lt.tm_hour


def _alpha(dt, demi_vie):
    """Poids EWMA pour un écart dt (secondes) ; dt <= 0 ou demi-vie nulle : aucun poids."""
    if not dt > 0 or not demi_vie > 0:
        return 0.0
    return 1.0 - 2.0 ** (-dt / demi_vie)


def _fini(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def _niveau_z(valeur, moyenne, variance, plancher):
    ecart = max(math.sqrt(max(variance, 0.0)), plancher if _fini(plancher) else 0.0, 1e-9)
    z = (valeur - moyenne) / ecart
    if z < 1:
        return 0
    if z < 2:
        return 1
    if z < 3:
        return 2
    return 3


class Reference:
    """Références longue (par tranche) et courte d'un ensemble de mesures."""

    def __init__(self, demi_vie_longue=7 * 86400, demi_vie_courte=3600, apprentissage=86400):
        self.demi_vie_longue = float(demi_vie_longue)
        self.demi_vie_courte = float(demi_vie_courte)
        self.apprentissage = float(apprentissage)
        # cle -> {"premiere", "court": {m, v, t}, "tranches": {"<n>": {...}}}
        self._cles = {}

    # -- mise à jour ---------------------------------------------------------------

    def observer(self, cle, valeur, t):
        """Enregistre un relevé de la mesure `cle` à l'instant `t` (epoch)."""
        if not (_fini(valeur) and _fini(t)):
            return
        c = self._cles.get(cle)
        if c is None:
            c = {"premiere": float(t), "court": None, "tranches": {}}
            self._cles[cle] = c
        c["premiere"] = min(c["premiere"], float(t))
        self._maj_courte(c, float(valeur), float(t))
        self._maj_longue(c, float(valeur), float(t))

    def _maj_courte(self, c, x, t):
        s = c["court"]
        if s is None:
            c["court"] = {"m": x, "v": 0.0, "t": t}
            return
        dt = min(max(t - s["t"], 0.0), DELTA_MAX_COURT)
        a = _alpha(dt, self.demi_vie_courte)
        diff = x - s["m"]
        s["m"] += a * diff
        s["v"] = (1.0 - a) * (s["v"] + a * diff * diff)
        s["t"] = t

    def _maj_longue(self, c, x, t):
        n = str(tranche(t))
        h = int(t // 3600)
        e = c["tranches"].get(n)
        if e is None:
            e = {"m": None, "v": 0.0, "tp": None, "h": h, "t0": t, "vn": 0, "vm": 0.0, "vq": 0.0}
            c["tranches"][n] = e
        if e["h"] != h:
            self._plier_visite(e)
            e["h"], e["t0"], e["vn"], e["vm"], e["vq"] = h, t, 0, 0.0, 0.0
        # Welford : moyenne et somme des carrés des écarts de la visite en cours
        e["vn"] += 1
        d = x - e["vm"]
        e["vm"] += d / e["vn"]
        e["vq"] += d * (x - e["vm"])

    def _plier_visite(self, e):
        """Intègre la visite terminée de la tranche dans la référence longue."""
        if e["vn"] <= 0:
            return
        mv = e["vm"]
        sv = e["vq"] / e["vn"]
        if e["m"] is None:
            e["m"], e["v"] = mv, sv
        else:
            a = _alpha(min(e["t0"] - e["tp"], ECART_MAX_VISITES), self.demi_vie_longue)
            diff = mv - e["m"]
            e["m"] += a * diff
            e["v"] = (1.0 - a) * (e["v"] + a * diff * diff) + a * sv
        e["tp"] = e["t0"]

    # -- lecture -------------------------------------------------------------------

    def niveau(self, cle, valeur, t, plancher):
        """Niveau 0..3 de `valeur` contre la référence ; None si la clé est inconnue."""
        c = self._cles.get(cle)
        if c is None or c["court"] is None or not (_fini(valeur) and _fini(t)):
            return None
        niveaux = []
        s = c["court"]
        niveaux.append(_niveau_z(valeur, s["m"], s["v"], plancher))
        e = c["tranches"].get(str(tranche(t)))
        if e is not None and e["m"] is not None:
            niveaux.append(_niveau_z(valeur, e["m"], e["v"], plancher))
        n = max(niveaux)
        if not (t - c["premiere"] >= self.apprentissage):
            n = min(n, 1)
        return n

    # -- persistance ---------------------------------------------------------------

    def vers_dict(self):
        """Représentation JSON de la référence."""
        return {
            "version": VERSION,
            "demi_vie_longue": self.demi_vie_longue,
            "demi_vie_courte": self.demi_vie_courte,
            "apprentissage": self.apprentissage,
            "cles": {k: {"premiere": c["premiere"],
                         "court": dict(c["court"]) if c["court"] else None,
                         "tranches": {n: dict(e) for n, e in c["tranches"].items()}}
                     for k, c in self._cles.items()},
        }

    @classmethod
    def depuis_dict(cls, d):
        """Reconstruit une référence ; toute anomalie donne une référence vide."""
        try:
            return cls._depuis_dict(d)
        except (TypeError, ValueError, KeyError, AttributeError, OverflowError):
            return cls()

    @classmethod
    def _depuis_dict(cls, d):
        if not isinstance(d, dict) or d.get("version") != VERSION:
            raise ValueError("version")
        params = [d.get(k) for k in ("demi_vie_longue", "demi_vie_courte", "apprentissage")]
        if not all(_fini(p) and p > 0 for p in params):
            raise ValueError("paramètres")
        ref = cls(*params)
        cles = d.get("cles")
        if not isinstance(cles, dict):
            raise ValueError("cles")
        for k, c in cles.items():
            if not isinstance(k, str) or not isinstance(c, dict) or not _fini(c.get("premiere")):
                raise ValueError("clé")
            court = c.get("court")
            if court is not None:
                court = _lire_champs(court, ("m", "v", "t"))
                if court["v"] < 0:
                    raise ValueError("variance")
            tr = c.get("tranches")
            if not isinstance(tr, dict):
                raise ValueError("tranches")
            tranches = {}
            for n, e in tr.items():
                if not (isinstance(n, str) and n.isdigit() and 0 <= int(n) <= 167 and isinstance(e, dict)):
                    raise ValueError("tranche")
                f = _lire_champs(e, ("v", "t0", "vm", "vq"), facultatifs=("m", "tp"))
                if not (isinstance(e.get("h"), int) and not isinstance(e.get("h"), bool)
                        and isinstance(e.get("vn"), int) and not isinstance(e.get("vn"), bool)
                        and e["vn"] >= 0 and f["v"] >= 0 and f["vq"] >= 0):
                    raise ValueError("tranche")
                if f["m"] is not None and f["tp"] is None:
                    raise ValueError("tranche")
                f["h"], f["vn"] = e["h"], e["vn"]
                tranches[n] = f
            ref._cles[k] = {"premiere": float(c["premiere"]), "court": court, "tranches": tranches}
        return ref


def _lire_champs(src, obligatoires, facultatifs=()):
    """Copie les champs numériques finis de `src` ; ValueError si l'un manque ou est invalide."""
    if not isinstance(src, dict):
        raise ValueError("structure")
    out = {}
    for k in obligatoires:
        if not _fini(src.get(k)):
            raise ValueError(k)
        out[k] = float(src[k])
    for k in facultatifs:
        v = src.get(k)
        if v is not None and not _fini(v):
            raise ValueError(k)
        out[k] = None if v is None else float(v)
    return out
