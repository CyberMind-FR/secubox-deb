# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: Éphéméride :: astronomie LOCALE — soleil, lune, phases. Aucun réseau, aucune dépendance.

Formules à basse précision (Soleil : éléments moyens ; Lune : série de P. Schlyter avec perturbations principales).
Précision visée : quelques minutes sur un lever/coucher du Soleil, une dizaine pour la Lune, quelques heures sur un
instant de phase — largement suffisant pour un tableau de bord, et jamais d'appel distant.

Lever et coucher se trouvent en BALAYANT l'altitude sur la journée LOCALE (de minuit à minuit dans le fuseau donné :
23 ou 25 h les jours de changement d'heure) puis en affinant chaque franchissement du seuil. Ce balayage rend les cas
limites naturels : s'il n'y a aucun franchissement, c'est jour polaire ou nuit polaire, sans formule spéciale.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

H0_SOLEIL = -0.833     # degrés : réfraction + demi-diamètre du disque
H0_LUNE = 0.125        # degrés : parallaxe moyenne comprise
MOIS_SYNODIQUE = 29.530588853
UA_KM = 149_597_870.7
RAYON_TERRE_KM = 6371.0
PAS_BALAYAGE = timedelta(minutes=5)

NOMS_PHASES = ["Nouvelle lune", "Premier croissant", "Premier quartier", "Gibbeuse croissante",
               "Pleine lune", "Gibbeuse décroissante", "Dernier quartier", "Dernier croissant"]
PHASES_PRINCIPALES = [(0.0, "Nouvelle lune"), (90.0, "Premier quartier"), (180.0, "Pleine lune"), (270.0, "Dernier quartier")]


@dataclass
class Soleil:
    lever: Optional[datetime]
    coucher: Optional[datetime]
    duree: timedelta
    progression: float          # 0 → 1 entre lever et coucher ; 0 avant le lever, 1 après le coucher
    etat: str                   # avant_lever | jour | apres_coucher | jour_polaire | nuit_polaire


@dataclass
class Lune:
    nom: str
    illumination: float         # pourcentage, 0..100
    age_jours: float
    croissante: bool
    lever: Optional[datetime]
    coucher: Optional[datetime]
    elongation: float           # degrés, 0..360 (0 = nouvelle lune)


@dataclass
class PhaseProchaine:
    nom: str
    quand: datetime


# ── temps ────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _exiger_aware(m: datetime) -> datetime:
    if m.tzinfo is None or m.utcoffset() is None:
        raise ValueError("un instant sans fuseau est refusé")
    return m


def jour_julien(m: datetime) -> float:
    u = _exiger_aware(m).astimezone(timezone.utc)
    return u.timestamp() / 86400.0 + 2440587.5


def _depuis_jj(jj: float, tz) -> datetime:
    return datetime.fromtimestamp((jj - 2440587.5) * 86400.0, tz=timezone.utc).astimezone(tz)


def _rad(x: float) -> float:
    return math.radians(x)


def _norm(x: float) -> float:
    return x % 360.0


# ── positions ────────────────────────────────────────────────────────────────────────────────────────────────────────

def _obliquite(jj: float) -> float:
    return _rad(23.439 - 0.0000004 * (jj - 2451545.0))


def _ecl_vers_equ(lon: float, lat: float, eps: float) -> tuple[float, float]:
    x = math.cos(lon) * math.cos(lat)
    y = math.sin(lon) * math.cos(lat) * math.cos(eps) - math.sin(lat) * math.sin(eps)
    z = math.sin(lon) * math.cos(lat) * math.sin(eps) + math.sin(lat) * math.cos(eps)
    return math.atan2(y, x), math.asin(max(-1.0, min(1.0, z)))


def _soleil_ecl(jj: float) -> tuple[float, float]:
    """(longitude écliptique en radians, distance en UA)."""
    n = jj - 2451545.0
    L = _norm(280.460 + 0.9856474 * n)
    g = _rad(_norm(357.528 + 0.9856003 * n))
    lam = _rad(L + 1.915 * math.sin(g) + 0.020 * math.sin(2 * g))
    R = 1.00014 - 0.01671 * math.cos(g) - 0.00014 * math.cos(2 * g)
    return lam, R


def _lune_ecl(jj: float) -> tuple[float, float, float]:
    """(longitude, latitude en radians, distance en rayons terrestres) — série de Schlyter."""
    d = jj - 2451543.5
    N = _norm(125.1228 - 0.0529538083 * d)
    w = _norm(318.0634 + 0.1643573223 * d)
    i = 5.1454
    a = 60.2666
    e = 0.054900
    M = _norm(115.3654 + 13.0649929509 * d)
    Ms = _norm(356.0470 + 0.9856002585 * d)
    ws = _norm(282.9404 + 4.70935e-5 * d)
    Lm = _norm(M + w + N)
    Ls = _norm(Ms + ws)
    D = _norm(Lm - Ls)
    F = _norm(Lm - N)
    Mr = _rad(M)
    E = M + math.degrees(e * math.sin(Mr) * (1 + e * math.cos(Mr)))
    for _ in range(8):
        Er = _rad(E)
        dE = (E - math.degrees(e * math.sin(Er)) - M) / (1 - e * math.cos(Er))
        E -= dE
        if abs(dE) < 1e-6:
            break
    Er = _rad(E)
    xv = a * (math.cos(Er) - e)
    yv = a * math.sqrt(1 - e * e) * math.sin(Er)
    v = math.atan2(yv, xv)
    r = math.hypot(xv, yv)
    Nr, ir, vw = _rad(N), _rad(i), v + _rad(w)
    xh = r * (math.cos(Nr) * math.cos(vw) - math.sin(Nr) * math.sin(vw) * math.cos(ir))
    yh = r * (math.sin(Nr) * math.cos(vw) + math.cos(Nr) * math.sin(vw) * math.cos(ir))
    zh = r * math.sin(vw) * math.sin(ir)
    lon = math.degrees(math.atan2(yh, xh))
    lat = math.degrees(math.atan2(zh, math.hypot(xh, yh)))
    s = lambda x: math.sin(_rad(x))     # noqa: E731
    c = lambda x: math.cos(_rad(x))     # noqa: E731
    lon += (-1.274 * s(M - 2 * D) + 0.658 * s(2 * D) - 0.186 * s(Ms) - 0.059 * s(2 * M - 2 * D)
            - 0.057 * s(M - 2 * D + Ms) + 0.053 * s(M + 2 * D) + 0.046 * s(2 * D - Ms) + 0.041 * s(M - Ms)
            - 0.035 * s(D) - 0.031 * s(M + Ms) - 0.015 * s(2 * F - 2 * D) + 0.011 * s(M - 4 * D))
    lat += (-0.173 * s(F - 2 * D) - 0.055 * s(M - F - 2 * D) - 0.046 * s(M + F - 2 * D)
            + 0.033 * s(F + 2 * D) + 0.017 * s(2 * M + F))
    r += -0.58 * c(M - 2 * D) - 0.46 * c(2 * D)
    return _rad(lon), _rad(lat), r


def _altitude(ra: float, dec: float, jj: float, lat: float, lon: float) -> float:
    """Altitude en degrés ; `lon` positive vers l'est."""
    gmst = _norm(280.46061837 + 360.98564736629 * (jj - 2451545.0))
    H = _rad(gmst + lon) - ra
    la = _rad(lat)
    s = math.sin(la) * math.sin(dec) + math.cos(la) * math.cos(dec) * math.cos(H)
    return math.degrees(math.asin(max(-1.0, min(1.0, s))))


def _alt_soleil(jj: float, lat: float, lon: float) -> float:
    lam, _ = _soleil_ecl(jj)
    ra, dec = _ecl_vers_equ(lam, 0.0, _obliquite(jj))
    return _altitude(ra, dec, jj, lat, lon)


def _alt_lune(jj: float, lat: float, lon: float) -> float:
    lo, la, _ = _lune_ecl(jj)
    ra, dec = _ecl_vers_equ(lo, la, _obliquite(jj))
    return _altitude(ra, dec, jj, lat, lon)


# ── lever / coucher par balayage ─────────────────────────────────────────────────────────────────────────────────────

def _bornes_du_jour_local(m: datetime) -> tuple[datetime, datetime]:
    tz = m.tzinfo
    debut = datetime(m.year, m.month, m.day, tzinfo=tz)
    suivant = (debut + timedelta(days=1, hours=12)).date()
    return debut, datetime(suivant.year, suivant.month, suivant.day, tzinfo=tz)


def _franchissements(fonction, seuil: float, debut: datetime, fin: datetime, tz):
    """(levers, couchers) : instants où `fonction(jj) - seuil` change de signe sur [debut, fin)."""
    j0, j1 = jour_julien(debut), jour_julien(fin)
    pas = PAS_BALAYAGE.total_seconds() / 86400.0
    levers, couchers = [], []
    a, fa = j0, fonction(j0) - seuil
    while a < j1:
        b = min(a + pas, j1)
        fb = fonction(b) - seuil
        if (fa < 0) != (fb < 0):
            lo, hi, flo = a, b, fa
            for _ in range(30):
                mid = (lo + hi) / 2
                fm = fonction(mid) - seuil
                if (fm < 0) == (flo < 0):
                    lo, flo = mid, fm
                else:
                    hi = mid
            (levers if fb >= 0 else couchers).append(_depuis_jj((lo + hi) / 2, tz))
        a, fa = b, fb
    return levers, couchers


def soleil(m: datetime, lat: float, lon: float) -> Soleil:
    _exiger_aware(m)
    debut, fin = _bornes_du_jour_local(m)
    levers, couchers = _franchissements(lambda j: _alt_soleil(j, lat, lon), H0_SOLEIL, debut, fin, m.tzinfo)
    lever = levers[0] if levers else None
    coucher = couchers[0] if couchers else None
    jour = (fin - debut).total_seconds()
    avance = min(max((m - debut).total_seconds() / jour, 0.0), 1.0)
    if lever is None and coucher is None:
        milieu = _alt_soleil(jour_julien(debut) + (jour / 86400.0) / 2, lat, lon)
        if milieu > H0_SOLEIL:
            return Soleil(None, None, timedelta(hours=24), avance, "jour_polaire")
        return Soleil(None, None, timedelta(0), 0.0, "nuit_polaire")
    if lever is not None and coucher is not None and lever < coucher:
        if m < lever:
            return Soleil(lever, coucher, coucher - lever, 0.0, "avant_lever")
        if m > coucher:
            return Soleil(lever, coucher, coucher - lever, 1.0, "apres_coucher")
        return Soleil(lever, coucher, coucher - lever, (m - lever) / (coucher - lever), "jour")
    if lever is None:                      # le soleil se couche mais ne s'est pas levé dans la journée (haute latitude)
        etat = "jour" if m <= coucher else "apres_coucher"
        return Soleil(None, coucher, coucher - debut, min(max((m - debut) / (coucher - debut), 0.0), 1.0), etat)
    if coucher is None or coucher < lever:  # il se lève et ne se couche pas dans la journée
        fin_jour = coucher if coucher is not None and coucher > lever else fin
        if m < lever:
            return Soleil(lever, None, fin_jour - lever, 0.0, "avant_lever")
        return Soleil(lever, None if coucher is None else coucher, fin_jour - lever,
                      min((m - lever) / (fin_jour - lever), 1.0), "jour")
    return Soleil(lever, coucher, coucher - lever, avance, "jour")


# ── lune ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

def _elongation(jj: float) -> float:
    lam_s, _ = _soleil_ecl(jj)
    lam_l, _, _ = _lune_ecl(jj)
    return _norm(math.degrees(lam_l - lam_s))


def nom_de_phase(elongation: float) -> str:
    return NOMS_PHASES[int(((elongation + 22.5) % 360.0) // 45.0)]


def lune(m: datetime, lat: float, lon: float) -> Lune:
    _exiger_aware(m)
    jj = jour_julien(m)
    lam_s, R = _soleil_ecl(jj)
    lam_l, lat_l, r = _lune_ecl(jj)
    elong = _norm(math.degrees(lam_l - lam_s))
    psi = math.acos(max(-1.0, min(1.0, math.cos(lat_l) * math.cos(lam_l - lam_s))))
    rs, rm = R * UA_KM, r * RAYON_TERRE_KM
    i = math.atan2(rs * math.sin(psi), rm - rs * math.cos(psi))
    illum = (1 + math.cos(i)) / 2 * 100.0
    debut, fin = _bornes_du_jour_local(m)
    levers, couchers = _franchissements(lambda j: _alt_lune(j, lat, lon), H0_LUNE, debut, fin, m.tzinfo)
    return Lune(nom=nom_de_phase(elong), illumination=round(illum, 1), age_jours=round(elong / 360.0 * MOIS_SYNODIQUE, 1),
                croissante=elong < 180.0, lever=levers[0] if levers else None, coucher=couchers[0] if couchers else None,
                elongation=round(elong, 2))


def prochaine_phase(m: datetime) -> PhaseProchaine:
    """La prochaine phase principale (nouvelle lune, premier quartier, pleine lune, dernier quartier) après `m`."""
    _exiger_aware(m)
    j0 = jour_julien(m)
    meilleur: Optional[PhaseProchaine] = None
    for cible, nom in PHASES_PRINCIPALES:
        f = lambda j: ((_elongation(j) - cible + 180.0) % 360.0) - 180.0      # noqa: E731
        a, fa = j0, f(j0)
        pas = 0.25
        while a < j0 + MOIS_SYNODIQUE + 2:
            b = a + pas
            fb = f(b)
            if fa < 0 <= fb and (fb - fa) < 90:                                # franchissement croissant, pas le saut ±180
                lo, hi = a, b
                for _ in range(40):
                    mid = (lo + hi) / 2
                    if f(mid) < 0:
                        lo = mid
                    else:
                        hi = mid
                q = _depuis_jj((lo + hi) / 2, m.tzinfo)
                if meilleur is None or q < meilleur.quand:
                    meilleur = PhaseProchaine(nom, q)
                break
            a, fa = b, fb
    assert meilleur is not None
    return meilleur
