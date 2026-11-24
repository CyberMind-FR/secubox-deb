# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""#3907 — entrées/sorties de la box, lues sans root : débits et occupation par disque physique (/proc/diskstats),
pression (/proc/pressure, avg10), swap (/proc/vmstat), et services qui écrivent le plus (io.stat des cgroups systemd).

Les débits se calculent entre deux relevés : le premier n'en a pas (None, « première mesure »). Deux relevés à moins
de 2 s rendent le précédent, pour qu'un rafraîchissement rapproché ne divise pas par un intervalle minuscule.
Un compteur qui recule (service relancé, disque retiré) ne donne jamais un débit négatif : il est ignoré ce tour-ci.
"""
from __future__ import annotations

import re
import threading
from pathlib import Path

DISQUE_PHYSIQUE = re.compile(r"^(sd[a-z]+|vd[a-z]+|nvme\d+n\d+|mmcblk\d+)$")
SECTEUR = 512
INTERVALLE_MIN_S = 2.0
ECRIVAINS_MAX = 5
# Unités comptées une seule fois : services du système (et de ses sous-tranches) et conteneurs LXC entiers.
MOTIFS_UNITES = ("system.slice/*.service", "system.slice/*.slice/*.service", "lxc.payload.*")


def _lire(p: Path) -> str | None:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def lire_disques(texte: str) -> dict:
    """{disque: (lectures, secteurs lus, écritures, secteurs écrits, ms occupés)} des disques entiers seulement."""
    out = {}
    for ligne in (texte or "").splitlines():
        c = ligne.split()
        if len(c) < 14 or not DISQUE_PHYSIQUE.match(c[2]):
            continue
        try:
            out[c[2]] = (int(c[3]), int(c[5]), int(c[7]), int(c[9]), int(c[12]))
        except ValueError:
            continue
    return out


def lire_pression(texte: str | None) -> dict:
    out = {"some": None, "full": None}
    for ligne in (texte or "").splitlines():
        c = ligne.split()
        if c and c[0] in out:
            for champ in c[1:]:
                if champ.startswith("avg10="):
                    try:
                        out[c[0]] = float(champ[6:])
                    except ValueError:
                        pass
    return out


def lire_swap(texte: str | None) -> tuple:
    v = {}
    for ligne in (texte or "").splitlines():
        c = ligne.split()
        if len(c) == 2 and c[0] in ("pswpin", "pswpout"):
            try:
                v[c[0]] = int(c[1])
            except ValueError:
                pass
    return v.get("pswpin"), v.get("pswpout")


def lire_ecritures_unites(racine: Path) -> dict:
    """{unité: octets écrits cumulés, tous disques}."""
    out = {}
    for motif in MOTIFS_UNITES:
        try:
            dossiers = list(racine.glob(motif))
        except OSError:
            continue
        for d in dossiers:
            texte = _lire(d / "io.stat")
            if texte is None:
                continue
            total = 0
            for ligne in texte.splitlines():
                for champ in ligne.split()[1:]:
                    if champ.startswith("wbytes="):
                        try:
                            total += int(champ[7:])
                        except ValueError:
                            pass
            out[d.name] = total
    return out


def _debit(avant, apres, dt):
    if avant is None or apres is None or dt is None or apres < avant:
        return None
    return round((apres - avant) / dt, 1)


class Mesure:
    def __init__(self, racine_proc: Path = Path("/proc"), racine_cg: Path = Path("/sys/fs/cgroup")):
        self.proc, self.cg = Path(racine_proc), Path(racine_cg)
        self._verrou = threading.Lock()
        self._prec: dict | None = None
        self._dernier: dict | None = None

    def _brut(self, maintenant: float) -> dict:
        return {"t": maintenant, "disques": lire_disques(_lire(self.proc / "diskstats") or ""),
                "swap": lire_swap(_lire(self.proc / "vmstat")), "unites": lire_ecritures_unites(self.cg)}

    def releve(self, maintenant: float) -> dict:
        with self._verrou:
            if self._prec and self._dernier and maintenant - self._prec["t"] < INTERVALLE_MIN_S:
                return self._dernier
            brut = self._brut(maintenant)
            prec = self._prec
            dt = (maintenant - prec["t"]) if prec and maintenant > prec["t"] else None
            disques = []
            for nom, (rio, rsec, wio, wsec, ms) in sorted(brut["disques"].items()):
                a = prec["disques"].get(nom) if dt else None
                g = (lambda i, x: _debit(a[i], x, dt)) if a else (lambda i, x: None)
                lu, ecrit = g(1, rsec), g(3, wsec)
                occupe = g(4, ms)
                disques.append({"nom": nom,
                                "lecture_o_s": None if lu is None else lu * SECTEUR,
                                "ecriture_o_s": None if ecrit is None else ecrit * SECTEUR,
                                "lectures_s": g(0, rio), "ecritures_s": g(2, wio),
                                "occupe_pct": None if occupe is None else min(100.0, round(occupe / 10, 1))})
            sw = brut["swap"]
            psw = prec["swap"] if dt else (None, None)
            ecrivains = []
            if dt:
                for unite, w in brut["unites"].items():
                    d = _debit(prec["unites"].get(unite), w, dt)
                    if d:
                        ecrivains.append({"unite": unite, "ecriture_o_s": d})
                ecrivains.sort(key=lambda x: -x["ecriture_o_s"])
            r = {"intervalle_s": round(dt, 1) if dt else None, "disques": disques,
                 "pression": {k: lire_pression(_lire(self.proc / "pressure" / k)) for k in ("cpu", "memory", "io")},
                 "swap": {"entrees_s": _debit(psw[0], sw[0], dt), "sorties_s": _debit(psw[1], sw[1], dt)},
                 "ecrivains": ecrivains[:ECRIVAINS_MAX]}
            self._prec, self._dernier = brut, r
            return r
