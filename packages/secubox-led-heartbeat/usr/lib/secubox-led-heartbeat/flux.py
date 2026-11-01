# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Collecteur secubox-led-flux de la LED de supervision (ref #3361).

Toutes les 10 s : relevés bruts (releves.py, dont les compteurs nftables sbx_drop_* publiés
par l'unité root secubox-led-nft dans /run/secubox-led-nft/nft.json), conversion
des compteurs cumulés en débit par minute, niveau 0..4 de chaque mesure contre la
référence propre à la box, puis publication atomique de /run/secubox-leds/flux.json :
  {"genere_le": <epoch>, "niveaux": {"<cle>": 0..4|null},
   "apprentissage": [<clés encore en apprentissage, triées>]}
Une source apparue tard n'apprend que pour elle : le moteur colore clé par clé.
Le niveau est évalué AVANT l'observation du même relevé (contrat de Reference).
La référence est sauvée au démarrage, toutes les 15 min et à l'arrêt (SIGTERM).
"""
import json
import math
import os
import signal
import sys
import time
import tomllib
from pathlib import Path

from reference import Reference
import releves as _releves

PERIODE_S = 10.0
SAUVEGARDE_S = 900.0
CHEMIN_FLUX = Path("/run/secubox-leds/flux.json")
CHEMIN_REF = Path("/var/lib/secubox-leds/reference.json")
CHEMIN_CONFIG = Path("/etc/secubox/leds.toml")
LIMITE_CONFIG = 1024 * 1024
LIMITE_REF = 16 * 1024 * 1024

# Compteurs cumulés : convertis en débit par minute avant niveau et observation.
CUMULES = frozenset({"reseau.octets_in", "reseau.octets_out", "fw.paquets_in", "fw.paquets_out",
                     "fw.bloques", "waf.blocages", "adguard.requetes"})
# Niveau 4 absolu, prioritaire sur le relatif, dès que la valeur dépasse 0.
ABSOLUS = frozenset({"services.arretes", "actor.critiques"})

# Planchers de dispersion (#3361, point 4 du plan) : une box calme ne passe pas au jaune
# pour 2 événements. Un compteur relevé toutes les 10 s et converti en débit par minute
# multiplie chaque écart par 6 : 2 événements = 12/min, d'où 15 ; 20 événements = 120/min
# alertent toujours. Les jauges de comptage (actor.*, services.degrades) : 2.5.
PLANCHER_JAUGE = 1.0
PLANCHER_COMPTAGE = 2.5
PLANCHER_DEBIT = 15.0
PLANCHER_PAQUETS = 60.0
PLANCHER_OCTETS = 50000.0
PLANCHERS_DEFAUT = {
    "reseau.octets_in": PLANCHER_OCTETS, "reseau.octets_out": PLANCHER_OCTETS,
    "fw.paquets_in": PLANCHER_PAQUETS, "fw.paquets_out": PLANCHER_PAQUETS,
    "fw.bloques": PLANCHER_DEBIT, "waf.blocages": PLANCHER_DEBIT,
    "adguard.requetes": PLANCHER_DEBIT,
    "actor.evenements": PLANCHER_COMPTAGE, "actor.suspects": PLANCHER_COMPTAGE,
    "actor.critiques": PLANCHER_COMPTAGE, "services.degrades": PLANCHER_COMPTAGE,
}


def plancher(planchers, cle):
    """Plancher de dispersion d'une clé : surcharge, sinon défaut, sinon jauge de comptage."""
    p = planchers.get(cle)
    if p is None:
        p = PLANCHERS_DEFAUT.get(cle, PLANCHER_JAUGE)
    return float(p)


def lire_planchers(chemin=CHEMIN_CONFIG):
    """Planchers de dispersion de [flux.planchers] dans leds.toml (ref #3361).

    Les défauts de PLANCHERS_DEFAUT, surchargés clé par clé. Lecture tolérante : fichier
    absent ou illisible, table absente, valeur non numérique, booléenne, non finie ou
    <= 0 : le défaut s'applique (message sur stderr), le collecteur démarre toujours.
    """
    planchers = dict(PLANCHERS_DEFAUT)
    try:
        with open(chemin, "rb") as f:
            brut = f.read(LIMITE_CONFIG + 1)
        if len(brut) > LIMITE_CONFIG:
            raise ValueError("trop gros")
        table = tomllib.loads(brut.decode("utf-8")).get("flux", {})
    except FileNotFoundError:
        return planchers
    except (OSError, ValueError, RecursionError) as e:  # TOMLDecodeError et UnicodeError en sont
        print(f"secubox-led-flux : {chemin} illisible, planchers par défaut ({e})", file=sys.stderr)
        return planchers
    table = table.get("planchers") if isinstance(table, dict) else None
    if table is None:
        return planchers
    if not isinstance(table, dict):
        print("secubox-led-flux : flux.planchers n'est pas une table, planchers par défaut",
              file=sys.stderr)
        return planchers
    for cle, v in table.items():
        ok = (isinstance(v, (int, float)) and not isinstance(v, bool)
              and math.isfinite(v) and v > 0)
        if ok:
            planchers[cle] = float(v)
        else:
            print(f"secubox-led-flux : flux.planchers.{cle} = {v!r} invalide, défaut "
                  f"{planchers.get(cle, PLANCHER_JAUGE)}", file=sys.stderr)
    return planchers


def pas_de_collecte(ref, prec, valeurs, t, planchers):
    """Niveaux 0..4 (ou None) de `valeurs` à l'instant `t` ; met à jour `ref` et `prec`.

    `prec` garde, pour chaque compteur cumulé, son dernier relevé brut (valeur, t).
    Un compteur qui recule (remis à zéro) est ignoré pour ce relevé : ni niveau ni
    observation, la base repart de la nouvelle valeur.
    """
    niveaux = {}
    for cle, brut in valeurs.items():
        valeur = brut
        if cle in CUMULES:
            ancien = prec.get(cle)
            prec[cle] = (brut, t)
            if ancien is None:
                niveaux[cle] = None
                continue
            dv, dt = brut - ancien[0], t - ancien[1]
            if dv < 0 or not dt > 0:
                niveaux[cle] = None
                continue
            valeur = dv * 60.0 / dt
        n = ref.niveau(cle, valeur, t, plancher(planchers, cle))
        if cle in ABSOLUS and valeur > 0:
            n = 4
        ref.observer(cle, valeur, t)
        niveaux[cle] = n
    return niveaux


def ecrire_atomique(chemin, donnees, mode):
    """Écrit `donnees` (JSON) dans `chemin` : fichier .tmp complet, puis os.replace."""
    chemin = Path(chemin)
    tmp = chemin.with_name(chemin.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(donnees, f, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def charger_reference(chemin):
    """Référence persistée ; fichier absent, illisible ou corrompu : référence vide."""
    try:
        with open(chemin, "rb") as f:
            brut = f.read(LIMITE_REF + 1)
        if len(brut) > LIMITE_REF:
            raise ValueError("trop gros")
        d = json.loads(brut)
    except FileNotFoundError:
        return Reference()
    except (OSError, ValueError, RecursionError) as e:
        print(f"secubox-led-flux : référence illisible, réapprentissage ({e})", file=sys.stderr)
        return Reference()
    ref = Reference.depuis_dict(d)
    if d and not ref.vers_dict()["cles"]:
        print("secubox-led-flux : référence illisible, réapprentissage", file=sys.stderr)
    return ref


class Collecteur:
    """État du collecteur : référence, derniers compteurs, échéance de sauvegarde."""

    def __init__(self, chemin_flux=CHEMIN_FLUX, chemin_ref=CHEMIN_REF, lire=None,
                 planchers=None, chemin_config=CHEMIN_CONFIG):
        self.chemin_flux = Path(chemin_flux)
        self.chemin_ref = Path(chemin_ref)
        self.lire = lire or _releves.releves
        self.chemin_config = Path(chemin_config)
        self.planchers_fournis = planchers is not None
        self.planchers = dict(planchers or {})
        self.ref = Reference()
        self.prec = {}
        self.prochaine_sauvegarde = 0.0

    def sauver_reference(self, t):
        try:
            ecrire_atomique(self.chemin_ref, self.ref.vers_dict(), 0o640)
        except OSError as e:
            print(f"secubox-led-flux : référence non sauvée ({e})", file=sys.stderr)

    def demarrer(self, t):
        if not self.planchers_fournis:
            self.planchers = lire_planchers(self.chemin_config)
        self.ref = charger_reference(self.chemin_ref)
        self.sauver_reference(t)
        self.prochaine_sauvegarde = t + SAUVEGARDE_S

    def passage(self, t):
        valeurs = self.lire()
        niveaux = pas_de_collecte(self.ref, self.prec, valeurs, t, self.planchers)
        apprentissage = sorted(c for c in valeurs if self.ref.en_apprentissage(c, t))
        try:
            ecrire_atomique(self.chemin_flux, {"genere_le": t, "niveaux": niveaux,
                                               "apprentissage": apprentissage}, 0o644)
        except OSError as e:
            print(f"secubox-led-flux : flux.json non écrit ({e})", file=sys.stderr)
        if t >= self.prochaine_sauvegarde:
            self.sauver_reference(t)
            self.prochaine_sauvegarde = t + SAUVEGARDE_S

    def arreter(self, t):
        self.sauver_reference(t)


def main():
    c = Collecteur()
    fin = []
    signal.signal(signal.SIGTERM, lambda *_: fin.append(1))
    signal.signal(signal.SIGINT, lambda *_: fin.append(1))
    c.demarrer(time.time())
    prochain = time.monotonic()
    while not fin:
        try:
            c.passage(time.time())
        except Exception as e:  # un relevé raté ne doit pas tuer le collecteur
            print(f"secubox-led-flux : passage en échec ({e!r})", file=sys.stderr)
        prochain += PERIODE_S
        attente = prochain - time.monotonic()
        if attente < 0:
            prochain = time.monotonic()
            attente = 0
        fin_attente = time.monotonic() + attente
        while not fin and time.monotonic() < fin_attente:
            time.sleep(min(1.0, fin_attente - time.monotonic()))
    c.arreter(time.time())
    return 0
