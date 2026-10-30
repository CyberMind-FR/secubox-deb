# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Moteur d'affichage en couches des 3 LED RGB MOCHAbin (IS31FL3199, ref #3290).

Grammaire du propriétaire (2026-10-30) :
  formes  : par_led (une mesure par LED), jauge (niveau = nombre de LEDs allumées),
            mono / double / triple (une mesure portée par 1, 2 ou 3 LEDs),
            etale (séquence déphasée sur les trois LEDs), rotatif (une LED qui défile) ;
            plusieurs couches mono consécutives tournent par fenêtre de trois.
  rythmes : fixe, respiration (rampe logicielle à 3 paliers), pulsation (fréquence
            proportionnelle au niveau), eclats (N éclats = niveau).
  couches : liste ordonnée dans /etc/secubox/leds.toml, chacune précédée d'un repère
            (N éclats blancs sur la LED 2, N = rang de la couche, au plus 3).

Contraintes I²C (blocages mv64xxx de mai 2026) : images calculées en mémoire, un
canal n'est écrit que si sa valeur change, débit borné par un seau à jetons
(défaut 20 écritures/s tous canaux confondus). Le pilote leds-is31fl319x n'expose
pas les rampes matérielles de la puce (ni pattern ni blink_set) : la respiration
est logicielle, à faible résolution. Source absente ou périmée = « inconnu »
(gris-bleu faible fixe), jamais vert. Lecture seule, locale, sans réseau ni secret.
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None

log = logging.getLogger("secubox-led")

CONFIG = Path("/etc/secubox/leds.toml")
BASE_LEDS = "/sys/class/leds"
COULEURS = ("red", "green", "blue")
NB_LEDS = 3
OFF = (0, 0, 0)

FORMES = ("par_led", "jauge", "mono", "double", "triple", "etale", "rotatif")
RYTHMES = ("fixe", "respiration", "pulsation", "eclats")

# Palette validée par le propriétaire sur gk6 (2026-10-30).
PALETTE = {
    "rouge": (255, 0, 0), "vert": (0, 255, 0), "bleu": (0, 0, 255),
    "orange": (255, 80, 0), "jaune": (255, 200, 0), "violet": (150, 0, 255),
    "rose": (255, 20, 120), "cyan": (0, 220, 255), "turquoise": (0, 255, 90),
    "blanc_chaud": (255, 150, 60), "blanc": (255, 255, 255),
}
INCONNU = (40, 40, 80)          # gris-bleu faible : état inconnu
PALETTE_NIVEAU = ["vert", "jaune", "orange", "rouge"]

DEFAUT_DEBIT = 20
DEFAUT_LUMINOSITE = 0.6
DEFAUT_PAS = 0.1
DEFAUT_REPERE = 1.2
DEFAUT_MESURE = 5.0
DEFAUT_DUREE = 8.0
DEFAUT_PERIODE = {"fixe": 1.0, "respiration": 6.0, "pulsation": 3.0, "eclats": 3.0}

SOURCES_DEFAUT = {
    "cpu": {"type": "cpu", "chemin": "/proc/stat", "seuils": [50, 75, 90]},
    "memoire": {"type": "memoire", "chemin": "/proc/meminfo", "seuils": [60, 80, 92]},
    "es": {"type": "iowait", "chemin": "/proc/stat", "seuils": [5, 15, 30]},
    # Cache de secubox-metrics (30 s) : compteur cumulé des blocages du WAF.
    "attaques": {"type": "compteur_json", "chemin": "/var/cache/secubox/metrics-cache.json",
                 "cle": "waf.waf_blocked", "seuils": [1, 10, 60], "fraicheur_max": 300},
    # Même cache : connexions HTTPS établies (instantané, pas de journal relu).
    "visites": {"type": "jauge_json", "chemin": "/var/cache/secubox/metrics-cache.json",
                "cle": "connections.https", "seuils": [1, 20, 100], "fraicheur_max": 300},
    # Alertes du SOC non acquittées ; une critique non vue = niveau 3.
    "alertes": {"type": "alertes_json", "chemin": "/var/lib/secubox/soc/alerts.json",
                "seuils": [1, 3, 10], "fraicheur_max": 0},
}
COUCHES_DEFAUT = [
    {"nom": "systeme", "sources": ["cpu", "memoire", "es"], "forme": "par_led",
     "palette": ["vert", "jaune", "orange", "rouge"], "rythme": "respiration", "duree": 8},
    {"nom": "trafic", "sources": ["attaques", "visites", "alertes"], "forme": "par_led",
     "palette": ["cyan", "bleu", "violet", "rose"], "rythme": "pulsation", "duree": 8},
]


def niveau(valeur: float, seuils) -> int:
    """Valeur mesurée -> niveau 0..3 (seuils croissants)."""
    n = 0
    for s in seuils:
        if valeur >= s:
            n += 1
    return n


def _seuils_valides(s) -> bool:
    return (isinstance(s, list) and len(s) == 3
            and all(isinstance(x, (int, float)) and not isinstance(x, bool) for x in s)
            and s[0] < s[1] < s[2])


# ---------------------------------------------------------------- sources

class Source:
    """Mesure locale -> niveau 0..3, ou None (inconnu)."""

    def __init__(self, nom: str, opts: dict):
        self.nom = nom
        defaut = SOURCES_DEFAUT.get(nom, {})
        self.chemin = Path(opts.get("chemin") or defaut.get("chemin") or "/nonexistent")
        self.seuils = opts.get("seuils", defaut.get("seuils", [1, 2, 3]))
        self.cle = opts.get("cle", defaut.get("cle", ""))
        self.fraicheur_max = opts.get("fraicheur_max", defaut.get("fraicheur_max", 0))

    def lire(self, maintenant: float):
        try:
            return self._lire(maintenant)
        except (OSError, ValueError, TypeError, KeyError, IndexError, ZeroDivisionError):
            return None

    def _lire(self, maintenant):  # pragma: no cover - abstrait
        raise NotImplementedError

    def _json(self):
        if self.fraicheur_max and time.time() - self.chemin.stat().st_mtime > self.fraicheur_max:
            return None
        return json.loads(self.chemin.read_text())

    def _cle(self, donnees):
        for morceau in self.cle.split("."):
            donnees = donnees[morceau]
        return float(donnees)


class _SourceStat(Source):
    def __init__(self, nom, opts):
        super().__init__(nom, opts)
        self._prec = None

    def _champs(self):
        with open(self.chemin) as f:
            ligne = f.readline().split()
        if not ligne or ligne[0] != "cpu":
            raise ValueError("pas de ligne cpu")
        v = [int(x) for x in ligne[1:9]]
        return v + [0] * (8 - len(v))

    def _lire(self, maintenant):
        cour = self._champs()
        prec, self._prec = self._prec, cour
        if prec is None:
            return None
        d = [c - p for c, p in zip(cour, prec)]
        total = sum(d)
        if total <= 0:
            return None
        return niveau(100.0 * self._part(d) / total, self.seuils)


class SourceCpu(_SourceStat):
    """Occupation CPU (hors idle et iowait) depuis /proc/stat."""

    def _part(self, d):
        return sum(d) - d[3] - d[4]


class SourceIowait(_SourceStat):
    """Part d'attente d'E/S (iowait) depuis /proc/stat."""

    def _part(self, d):
        return d[4]


class SourceMemoire(Source):
    """Mémoire utilisée = 100 - MemAvailable / MemTotal."""

    def _lire(self, maintenant):
        info = {}
        for ligne in self.chemin.read_text().splitlines():
            k, _, v = ligne.partition(":")
            if v.strip():
                info[k] = int(v.split()[0])
        return niveau(100.0 * (1 - info["MemAvailable"] / info["MemTotal"]), self.seuils)


class SourceJaugeJson(Source):
    """Valeur instantanée lue à une clé pointée d'un fichier JSON d'état."""

    def _lire(self, maintenant):
        d = self._json()
        return None if d is None else niveau(self._cle(d), self.seuils)


class SourceCompteurJson(Source):
    """Compteur cumulé d'un fichier JSON -> débit par minute."""

    def __init__(self, nom, opts):
        super().__init__(nom, opts)
        self._prec = None

    def _lire(self, maintenant):
        d = self._json()
        if d is None:
            self._prec = None
            return None
        v = self._cle(d)
        prec, self._prec = self._prec, (maintenant, v)
        if prec is None or maintenant <= prec[0]:
            return None
        delta = v - prec[1]
        if delta < 0:                    # compteur remis à zéro : on repart
            delta = 0
        return niveau(delta * 60.0 / (maintenant - prec[0]), self.seuils)


class SourceAlertes(Source):
    """Alertes non acquittées (liste JSON) ; une critique non vue = niveau 3."""

    def _lire(self, maintenant):
        d = self._json()
        if d is None:
            return None
        if isinstance(d, dict):
            d = d.get("alerts", d.get("alertes", []))
        ouvertes = [a for a in d if isinstance(a, dict) and not a.get("acknowledged")]
        if any(a.get("severity") == "critical" for a in ouvertes):
            return 3
        return niveau(len(ouvertes), self.seuils)


TYPES_SOURCE = {
    "cpu": SourceCpu, "iowait": SourceIowait, "memoire": SourceMemoire,
    "jauge_json": SourceJaugeJson, "compteur_json": SourceCompteurJson,
    "alertes_json": SourceAlertes,
}


# ---------------------------------------------------------------- rythmes

def multiplicateur(rythme: str, t: float, n: int, periode: float) -> float:
    """Intensité 0..1 à l'instant t, en peu de paliers (peu d'écritures)."""
    if rythme == "respiration":
        phase = (t % periode) / periode
        tri = 1 - abs(2 * phase - 1)               # 0 -> 1 -> 0
        palier = round(tri * 2) / 2                # 3 paliers
        return 0.2 + 0.8 * palier
    if rythme == "pulsation":
        if n <= 0:
            return 0.3
        p = periode / n
        return 1.0 if (t % p) < p / 2 else 0.15
    if rythme == "eclats":
        if n <= 0:
            return 0.3
        x = t % periode
        k = int(x / 0.3)
        return 1.0 if k < n and (x - k * 0.3) < 0.15 else 0.1
    return 1.0


def periode_effective(rythme: str, n, periode: float) -> float:
    if rythme == "pulsation" and n:
        return periode / n
    return periode


def eclats_repere(rang: int) -> int:
    """Nombre d'éclats du repère d'une couche : son rang (1, 2, 3 au plus)."""
    return min(rang + 1, 3)


# ---------------------------------------------------------------- couches

class Couche:
    def __init__(self, d: dict, cfg: "Config"):
        self.cfg = cfg
        self.nom = str(d.get("nom") or "couche")
        src = d.get("sources")
        if isinstance(src, str):
            src = [src]
        if not isinstance(src, list) or not src or not all(isinstance(s, str) for s in src):
            log.warning("couche %s : sources invalides, couche ignorée -> [cpu]", self.nom)
            src = ["cpu"]
        self.sources = src
        self.forme = _choix(d.get("forme", "par_led"), FORMES, "par_led", self.nom, "forme")
        self.rythme = _choix(d.get("rythme", "fixe"), RYTHMES, "fixe", self.nom, "rythme")
        pal = d.get("palette", PALETTE_NIVEAU)
        if (not isinstance(pal, list) or len(pal) != 4
                or not all(isinstance(c, str) and c in cfg.palette for c in pal)):
            log.warning("couche %s : palette invalide %r -> %s", self.nom, pal, PALETTE_NIVEAU)
            pal = list(PALETTE_NIVEAU)
        self.palette = pal
        self.duree = _nombre(d.get("duree", DEFAUT_DUREE), 1, 600, DEFAUT_DUREE,
                             f"couche {self.nom} : duree")
        self.periode = _nombre(d.get("periode", DEFAUT_PERIODE[self.rythme]), 0.5, 60,
                               DEFAUT_PERIODE[self.rythme], f"couche {self.nom} : periode")
        leds = d.get("leds")
        if leds is not None and not (isinstance(leds, list) and leds
                                     and all(isinstance(i, int) and 1 <= i <= 3 for i in leds)):
            log.warning("couche %s : leds invalide %r, ignoré", self.nom, leds)
            leds = None
        self.leds = [i - 1 for i in leds] if leds else None

    def teinte(self, n, t: float):
        if n is None:
            return self.cfg.inconnu
        base = self.cfg.couleur(self.palette[max(0, min(3, n))])
        m = multiplicateur(self.rythme, t, n, self.periode)
        return tuple(int(round(c * m)) for c in base)

    def _leds_forme(self):
        if self.leds:
            return self.leds
        return {"mono": [0], "double": [0, 1]}.get(self.forme, [0, 1, 2])

    def image(self, t: float, niveaux: list):
        img = [OFF] * NB_LEDS
        if self.forme == "par_led":
            for i in range(min(NB_LEDS, len(niveaux))):
                img[i] = self.teinte(niveaux[i], t)
            return img
        n = niveaux[0] if niveaux else None
        if self.forme == "jauge":
            if n is None:
                img[0] = self.cfg.inconnu
            elif n == 0:
                img[0] = tuple(int(round(c * 0.25)) for c in self.teinte(0, t))
            else:
                for i in range(min(n, NB_LEDS)):
                    img[i] = self.teinte(n, t)
        elif self.forme == "etale":
            dephasage = periode_effective(self.rythme, n, self.periode) / NB_LEDS
            for i in range(NB_LEDS):
                img[i] = self.teinte(n, t - i * dephasage)
        elif self.forme == "rotatif":
            pas = 0.8 / (1 + (n or 0))
            pos = [0, 1, 2, 1][int(t / pas) % 4]
            img[pos] = self.teinte(n, t)
        else:                                       # mono / double / triple
            for i in self._leds_forme():
                img[i] = self.teinte(n, t)
        return img


def _choix(v, permis, defaut, nom, champ):
    if v not in permis:
        log.warning("couche %s : %s %r inconnu(e) -> %s", nom, champ, v, defaut)
        return defaut
    return v


def _nombre(v, mini, maxi, defaut, quoi):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not (mini <= v <= maxi):
        log.warning("%s = %r hors bornes [%s, %s] -> %s", quoi, v, mini, maxi, defaut)
        return defaut
    return v


# ---------------------------------------------------------------- configuration

class Config:
    def __init__(self):
        self.debit_max = DEFAUT_DEBIT
        self.luminosite = DEFAUT_LUMINOSITE
        self.pas = DEFAUT_PAS
        self.repere_duree = DEFAUT_REPERE
        self.periode_mesure = DEFAUT_MESURE
        self.base = BASE_LEDS
        self.reprise_auto = True
        self.palette = dict(PALETTE)
        self.sources: dict = {}
        self.couches: list = []

    def couleur(self, nom: str, luminosite=None):
        lum = self.luminosite if luminosite is None else luminosite
        return tuple(int(round(c * lum)) for c in self.palette[nom])

    @property
    def inconnu(self):
        return tuple(max(1, int(round(c * self.luminosite))) for c in INCONNU)


def charger_config(chemin) -> Config:
    """leds.toml -> Config ; toute valeur invalide est remplacée par son défaut
    avec un avertissement, un fichier illisible donne la configuration livrée."""
    cfg = Config()
    brut = {}
    if chemin is not None:
        try:
            with open(chemin, "rb") as f:
                brut = tomllib.load(f)
        except (OSError, ValueError, AttributeError) as e:
            log.warning("%s illisible (%s) : configuration par défaut", chemin, e)
            brut = {}
    m = brut.get("moteur", {}) if isinstance(brut.get("moteur"), dict) else {}
    cfg.debit_max = _nombre(m.get("debit_max", DEFAUT_DEBIT), 1, 100, DEFAUT_DEBIT,
                            "moteur.debit_max")
    cfg.luminosite = _nombre(m.get("luminosite", DEFAUT_LUMINOSITE), 0.05, 1.0,
                             DEFAUT_LUMINOSITE, "moteur.luminosite")
    cfg.pas = _nombre(m.get("pas", DEFAUT_PAS), 0.05, 1.0, DEFAUT_PAS, "moteur.pas")
    cfg.repere_duree = _nombre(m.get("repere_duree", DEFAUT_REPERE), 0, 5, DEFAUT_REPERE,
                               "moteur.repere_duree")
    cfg.periode_mesure = _nombre(m.get("periode_mesure", DEFAUT_MESURE), 1, 300,
                                 DEFAUT_MESURE, "moteur.periode_mesure")
    cfg.reprise_auto = bool(m.get("reprise_auto", True))

    for nom, rgb in (brut.get("couleurs") or {}).items():
        if (isinstance(rgb, list) and len(rgb) == 3
                and all(isinstance(c, int) and 0 <= c <= 255 for c in rgb)):
            cfg.palette[nom] = tuple(rgb)
        else:
            log.warning("couleurs.%s = %r invalide, ignorée", nom, rgb)

    defs = {k: dict(v) for k, v in SOURCES_DEFAUT.items()}
    for nom, opts in (brut.get("sources") or {}).items():
        if not isinstance(opts, dict):
            log.warning("sources.%s invalide, ignorée", nom)
            continue
        defs[nom] = {**defs.get(nom, {}), **opts}
    for nom, opts in defs.items():
        typ = opts.get("type")
        if typ not in TYPES_SOURCE:
            log.warning("sources.%s : type %r inconnu, ignorée", nom, typ)
            continue
        if not _seuils_valides(opts.get("seuils")):
            defaut = SOURCES_DEFAUT.get(nom, {}).get("seuils", [1, 2, 3])
            log.warning("sources.%s : seuils %r invalides -> %s", nom, opts.get("seuils"), defaut)
            opts["seuils"] = defaut
        cfg.sources[nom] = TYPES_SOURCE[typ](nom, opts)

    couches = brut.get("couche")
    if not isinstance(couches, list) or not couches:
        couches = COUCHES_DEFAUT
    for d in couches:
        if isinstance(d, dict):
            c = Couche(d, cfg)
            for s in c.sources:
                if s not in cfg.sources:
                    log.warning("couche %s : source %r inconnue (affichée « inconnu »)",
                                c.nom, s)
            cfg.couches.append(c)
    if not cfg.couches:
        cfg.couches = [Couche(d, cfg) for d in COUCHES_DEFAUT]
    return cfg


# ---------------------------------------------------------------- ordonnanceur

class Ordonnanceur:
    """Enchaîne les couches ; les couches mono consécutives forment un groupe
    rotatif (fenêtre de trois qui glisse d'une couche à chaque pas)."""

    def __init__(self, couches: list, cfg: Config):
        self.cfg = cfg
        self.entrees = []                           # (rang, [couches], rotatif)
        groupe = []
        for c in couches:
            if c.forme == "mono" and not c.leds:
                groupe.append(c)
                continue
            if groupe:
                self.entrees.append(groupe)
                groupe = []
            self.entrees.append([c])
        if groupe:
            self.entrees.append(groupe)

    def _duree(self, entree):
        if len(entree) > 1:
            pas = entree[0].duree
            return self.cfg.repere_duree + pas * (len(entree) if len(entree) > 3 else 1)
        return self.cfg.repere_duree + entree[0].duree

    def _situer(self, t: float):
        cycle = sum(self._duree(e) for e in self.entrees)
        x = t % cycle if cycle > 0 else 0
        for rang, e in enumerate(self.entrees):
            d = self._duree(e)
            if x < d:
                return rang, e, x
            x -= d
        return 0, self.entrees[0], 0.0             # pragma: no cover

    def position(self, t: float):
        _, e, x = self._situer(t)
        return e[0].nom, x < self.cfg.repere_duree

    def fenetre_mono(self, t: float):
        _, e, x = self._situer(t)
        if len(e) <= 3:
            return list(e)
        k = int(max(0.0, x - self.cfg.repere_duree) / e[0].duree)
        return [e[(k + j) % len(e)] for j in range(3)]

    def image(self, t: float, niveaux: dict):
        rang, e, x = self._situer(t)
        if x < self.cfg.repere_duree:
            n = eclats_repere(rang)
            k = int(x / 0.3)
            allume = k < n and (x - k * 0.3) < 0.15
            return [OFF, self.cfg.couleur("blanc") if allume else OFF, OFF]
        tl = x - self.cfg.repere_duree
        if len(e) == 1 and not (e[0].forme == "mono" and not e[0].leds):
            c = e[0]
            return c.image(tl, [niveaux.get(s) for s in c.sources])
        img = [OFF] * NB_LEDS
        for j, c in enumerate(self.fenetre_mono(t)):
            img[j] = c.teinte(niveaux.get(c.sources[0]), tl)
        return img

    def sources(self):
        return sorted({s for e in self.entrees for c in e for s in c.sources})


# ---------------------------------------------------------------- rendu

class EcrivainSysfs:
    def __init__(self, base=BASE_LEDS):
        self.base = Path(base)

    def ecrire(self, canal: str, valeur: int):
        with open(self.base / canal / "brightness", "w") as f:
            f.write(str(int(valeur)))

    def liberer_declencheurs(self):
        """Retire les déclencheurs noyau (heartbeat, timer) posés par
        secubox-leds/secubox-led-trigger : un seul écrivain sur la puce."""
        for i in range(1, NB_LEDS + 1):
            for c in COULEURS:
                try:
                    with open(self.base / f"{c}:led{i}" / "trigger", "w") as f:
                        f.write("none")
                except OSError:
                    pass
                time.sleep(0.05)


class EcrivainTexte:
    def __init__(self, horloge, flux=None):
        self.horloge = horloge
        self.flux = flux or sys.stdout

    def ecrire(self, canal, valeur):
        print(f"{self.horloge():8.2f} {canal} {valeur}", file=self.flux)


class Rendu:
    """Écrit seulement les canaux qui changent, au plus `debit_max` par
    seconde (seau à jetons), en tourniquet pour qu'aucun canal ne soit affamé."""

    def __init__(self, ecrivain, debit_max=DEFAUT_DEBIT, horloge=time.monotonic,
                 seuil_reprise=3, reprise=None, pause=time.sleep):
        self.ecrivain = ecrivain
        self.debit = float(debit_max)
        self.horloge = horloge
        self.jetons = float(debit_max)
        self.dernier = horloge()
        self.etat: dict = {}
        self.curseur = 0
        self.erreurs = 0
        self.seuil_reprise = seuil_reprise
        self.reprise = reprise
        self.pause = pause
        self.canaux = [f"{c}:led{i + 1}" for i in range(NB_LEDS) for c in COULEURS]

    def _recharger(self):
        t = self.horloge()
        self.jetons = min(self.debit, self.jetons + (t - self.dernier) * self.debit)
        self.dernier = t

    def afficher(self, img):
        self._recharger()
        voulu = {f"{c}:led{i + 1}": max(0, min(255, int(img[i][j])))
                 for i in range(NB_LEDS) for j, c in enumerate(COULEURS)}
        n = len(self.canaux)
        for k in range(n):
            if self.jetons < 1:
                return
            canal = self.canaux[(self.curseur + k) % n]
            if self.etat.get(canal) == voulu[canal]:
                continue
            self.jetons -= 1
            try:
                self.ecrivain.ecrire(canal, voulu[canal])
            except OSError as e:
                self.etat.pop(canal, None)
                self.erreurs += 1
                log.warning("écriture %s échouée (%s), %d/%d", canal, e, self.erreurs,
                            self.seuil_reprise)
                if self.erreurs >= self.seuil_reprise:
                    self.erreurs = 0
                    self.etat.clear()
                    if self.reprise:
                        self.reprise()
                continue
            self.erreurs = 0
            self.etat[canal] = voulu[canal]
        self.curseur = (self.curseur + 1) % n

    def eteindre(self):
        """Arrêt propre : les 9 canaux à 0, espacés de 50 ms."""
        for canal in self.canaux:
            try:
                self.ecrivain.ecrire(canal, 0)
                self.etat[canal] = 0
            except OSError:
                pass
            self.pause(0.05)


# ---------------------------------------------------------------- démon et démo

def _reprise_i2c():
    """Relance secubox-led-reset hors de notre unité (il arrête secubox-led-pulse)."""
    if not hasattr(_reprise_i2c, "dernier"):
        _reprise_i2c.dernier = -math.inf
    if time.monotonic() - _reprise_i2c.dernier < 600:
        return
    _reprise_i2c.dernier = time.monotonic()
    log.error("erreurs I2C répétées : secubox-led-reset lancé")
    subprocess.run(["systemd-run", "--no-block", "--collect", "--unit=secubox-led-reprise",
                    "/usr/sbin/secubox-led-reset"], check=False)


def boucle(cfg, ordo, rendu, horloge, attendre, duree=None, arret=lambda: False,
           niveaux_fixes=None):
    t0 = horloge()
    prochaine = t0
    niveaux = {}
    noms = ordo.sources()
    while not arret():
        t = horloge()
        if duree is not None and t - t0 >= duree:
            break
        if niveaux_fixes is not None:
            niveaux = niveaux_fixes(t - t0)
        elif t >= prochaine:
            niveaux = {n: cfg.sources[n].lire(t) if n in cfg.sources else None for n in noms}
            prochaine = t + cfg.periode_mesure
        rendu.afficher(ordo.image(t - t0, niveaux))
        attendre(cfg.pas)


def servir(cfg):
    arret = {"demande": False}

    def _stop(*_):
        arret["demande"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    ecr = EcrivainSysfs(cfg.base)
    ecr.liberer_declencheurs()
    rendu = Rendu(ecr, cfg.debit_max, reprise=_reprise_i2c if cfg.reprise_auto else None)
    ordo = Ordonnanceur(cfg.couches, cfg)
    log.info("couches : %s ; débit max %s écritures/s",
             ", ".join(c.nom for c in cfg.couches), cfg.debit_max)
    try:
        boucle(cfg, ordo, rendu, time.monotonic, time.sleep, arret=lambda: arret["demande"])
    finally:
        rendu.eteindre()
    return 0


def _couche_demo(forme, cfg, rythme=None):
    defaut = {"par_led": "respiration", "jauge": "fixe", "mono": "pulsation",
              "double": "pulsation", "triple": "respiration", "etale": "pulsation",
              "rotatif": "fixe"}
    sources = ["demo1", "demo2", "demo3"] if forme == "par_led" else ["demo1"]
    return Couche({"nom": f"demo-{forme}", "sources": sources, "forme": forme,
                   "rythme": rythme or defaut[forme], "duree": 600}, cfg)


def demo(args, cfg):
    """`demo <forme|couche|toutes>` : une forme avec des niveaux synthétiques
    (0, 1, 2, 3 puis inconnu, chacun `--duree`/5), ou une couche réelle."""
    if args.cible in FORMES:
        couches = [_couche_demo(args.cible, cfg, args.rythme)]
        cfg.repere_duree = 0

        def fixes(t):
            if args.niveau is not None:
                n = args.niveau
            else:
                n = [0, 1, 2, 3, None][int(t / max(args.duree / 5, 0.1)) % 5]
            if args.cible == "par_led" and args.niveau is None:
                return {"demo1": n, "demo2": None if n is None else (n + 1) % 4,
                        "demo3": None if n is None else (n + 2) % 4}
            return {"demo1": n, "demo2": n, "demo3": n}
    elif args.cible == "toutes":
        couches, fixes = cfg.couches, None
    else:
        couches = [c for c in cfg.couches if c.nom == args.cible]
        fixes = None
        if not couches:
            print(f"cible inconnue : {args.cible} (formes : {', '.join(FORMES)} ; couches : "
                  f"{', '.join(c.nom for c in cfg.couches)} ; toutes)", file=sys.stderr)
            return 2
    ordo = Ordonnanceur(couches, cfg)
    if args.simule:
        h = {"t": 0.0}
        horloge = lambda: h["t"]  # noqa: E731

        def attendre(d):
            h["t"] += d
        rendu = Rendu(EcrivainTexte(horloge), cfg.debit_max, horloge=horloge,
                      pause=lambda d: None)
    else:
        horloge, attendre = time.monotonic, time.sleep
        ecr = EcrivainSysfs(cfg.base)
        ecr.liberer_declencheurs()
        rendu = Rendu(ecr, cfg.debit_max)
    try:
        boucle(cfg, ordo, rendu, horloge, attendre, duree=args.duree, niveaux_fixes=fixes)
    except KeyboardInterrupt:
        pass
    finally:
        rendu.eteindre()
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="secubox-led-pulse",
                                description="Moteur d'affichage en couches des LED MOCHAbin")
    p.add_argument("--config", default=str(CONFIG))
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("servir", help="démon (défaut)")
    d = sub.add_parser("demo", help="montre une forme, une couche ou toutes")
    d.add_argument("cible", help=f"{' | '.join(FORMES)} | <nom de couche> | toutes")
    d.add_argument("--duree", type=float, default=20.0)
    d.add_argument("--niveau", type=int, choices=[0, 1, 2, 3])
    d.add_argument("--rythme", choices=RYTHMES)
    d.add_argument("--simule", action="store_true", help="sans matériel : écritures sur stdout")
    sub.add_parser("verifier", help="valide leds.toml et affiche les niveaux courants")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    chemin = Path(args.config)
    cfg = charger_config(chemin if chemin.exists() else None)
    if args.cmd == "demo":
        return demo(args, cfg)
    if args.cmd == "verifier":
        ordo = Ordonnanceur(cfg.couches, cfg)
        for n in ordo.sources():
            if n in cfg.sources:
                cfg.sources[n].lire(time.monotonic())   # premier relevé (deltas)
        time.sleep(1)
        for c in cfg.couches:
            niv = [cfg.sources[s].lire(time.monotonic()) if s in cfg.sources else None
                   for s in c.sources]
            print(f"{c.nom}: forme={c.forme} rythme={c.rythme} duree={c.duree}s "
                  + " ".join(f"{s}={'inconnu' if n is None else n}"
                             for s, n in zip(c.sources, niv)))
        return 0
    if os.environ.get("SECUBOX_TEST") != "1" and not Path(cfg.base, "red:led1").exists():
        log.error("aucune LED IS31FL3199 sous %s", cfg.base)
        return 1
    return servir(cfg)


if __name__ == "__main__":
    sys.exit(main())
