# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: autoload-agent :: le MOTEUR de provisioning (#2187, parent #2182)

    jeton + fichier de réponses signé → clé WireGuard → enrôlement → tunnel → plan → VALIDATION → installation → application

Chaque étape est idempotente et notée dans l'état (0600) : après une coupure ou un échec, `run()` reprend à la première étape non faite, sans rejouer
l'enrôlement (le jeton est à usage unique). Un parcours terminé ne refait rien.

La VALIDATION est un point d'injection (#2188) : le valideur reçoit le plan (profil, mode, paquets à installer) et rend vrai ou faux. SANS valideur
explicite, le défaut REFUSE : rien n'est installé tant qu'une décision n'a pas été prise.

Rien de ce qui vient du réseau n'est exécuté : la réponse du tunnel est validée avant d'être écrite (`tunnel.valider`), les noms de paquets de la
simulation apt sont filtrés par un motif strict, et toutes les commandes sont des listes d'arguments avec délai.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

try:
    from premier_pas import provision as V
except ImportError:                                                         # installé : /usr/lib/secubox/premier-pas
    sys.path.insert(0, "/usr/lib/secubox/premier-pas")
    from premier_pas import provision as V                                   # type: ignore[no-redef]

from . import tunnel as T

SECRETS = Path("/etc/secubox/secrets")
ETAPES = ("reponses", "cle", "enrolement", "tunnel", "plan", "validation", "installation", "application")
PROFILS_PAQUET = {"lite": "secubox-lite", "isp": "secubox-isp", "full": "secubox-full"}
TIMEOUT_COURT_S = 120
TIMEOUT_INSTALL_S = 3600
_PAQUET = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,80}$")


class EnrolementRefuse(Exception):
    """L'infrastructure a refusé le jeton ou la série (message uniforme)."""


class EtapeEchec(Exception):
    def __init__(self, etape: str, detail: str):
        super().__init__(f"{etape} : {detail}")
        self.etape, self.detail = etape, detail


@dataclass
class Config:
    reponses: Path
    signature: Path
    trousseau: Path
    racine_secrets: Path = SECRETS
    etat: Path = Path("/var/lib/secubox/autoload-agent/etat.json")
    cle_wg: Path = T.CLE_DEFAUT
    conf_wg: Path = T.CONF_DEFAUT
    rapport: Path = Path("/var/lib/secubox/autoload-agent/rapport.json")


@dataclass(frozen=True)
class Plan:
    profil: str
    mode: str
    paquets: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class Resultat:
    ok: bool
    etape: Optional[str] = None
    detail: str = ""


def _ecrit_prive(chemin: Path, texte: str) -> None:
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=".sbx-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
        os.replace(tmp, chemin)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _refus_par_defaut(plan: Plan) -> bool:
    return False


class Moteur:
    def __init__(self, cfg: Config, executeur=subprocess.run, enroleur: Optional[Callable] = None, valideur: Optional[Callable[[Plan], bool]] = None,
                 rapporteur: Optional[Callable[[str, int, int, bool], None]] = None, fabrique_valideur: Optional[Callable[[Dict], Callable[[Plan], bool]]] = None,
                 diffuseur: Optional[Callable[[Dict], None]] = None, horloge: Callable[[], float] = time.time):
        """`valideur` explicite prime ; sinon `fabrique_valideur(reponses)` en construit un d'après le mode du fichier de réponses ; sinon on REFUSE.
        `rapporteur(etape, faites, total, termine)` remonte la progression (best-effort : une panne ne l'arrête jamais)."""
        self.cfg, self.executeur, self.enroleur = cfg, executeur, enroleur
        self.valideur, self.rapporteur, self.fabrique_valideur = valideur, rapporteur, fabrique_valideur
        self.diffuseur, self._horloge = diffuseur, horloge
        self._ex = None                                                      # examen des réponses, gardé entre étapes d'un même passage
        self._cle_pub = None

    # ── état ─────────────────────────────────────────────────────────────────────────────────────────────────
    def _etat(self) -> dict:
        try:
            return json.loads(self.cfg.etat.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"faites": []}

    def _note(self, etat: dict, etape: str, **extra) -> None:
        etat["faites"] = [e for e in etat.get("faites", []) if e != etape] + [etape]
        etat.update(extra)
        _ecrit_prive(self.cfg.etat, json.dumps(etat, ensure_ascii=False, indent=1))

    def _cmd(self, argv: List[str], timeout: int = TIMEOUT_COURT_S):
        return self.executeur(argv, capture_output=True, text=True, timeout=timeout)

    # ── étapes ───────────────────────────────────────────────────────────────────────────────────────────────
    def _reponses(self):
        try:
            self._ex = V.charger_signe(self.cfg.reponses, self.cfg.signature, self.cfg.trousseau)
        except (V.SignatureInvalide, V.FichierInvalide) as e:
            raise EtapeEchec("reponses", str(e)) from e
        if not self._ex.complet:
            raise EtapeEchec("reponses", f"fichier incomplet ou invalide : {self._ex.manquantes} {self._ex.erreurs}")
        # la référence du jeton est déjà bornée par le schéma (#2184) ; on la re-vérifie par la résolution du chemin
        self._chemin_jeton()

    def _chemin_jeton(self) -> Path:
        ref = self._ex.profil["provision"]["jeton"]
        chemin = (self.cfg.racine_secrets / ref.rsplit("/", 1)[1])
        if not ref.startswith("ref:/etc/secubox/secrets/") or chemin.resolve().parent != self.cfg.racine_secrets.resolve():
            raise EtapeEchec("reponses", "référence de jeton hors du dossier des secrets")
        return chemin

    def _cle(self):
        try:
            self._cle_pub = T.assurer_cle(self.cfg.cle_wg, executeur=self.executeur)
        except T.TunnelErreur as e:
            raise EtapeEchec("cle", str(e)) from e

    def _enrolement(self, etat: dict):
        chemin = self._chemin_jeton()
        try:
            mode = chemin.stat().st_mode
            if mode & 0o077:
                raise EtapeEchec("enrolement", "le fichier du jeton est lisible par d'autres comptes")
            jeton = chemin.read_text(encoding="ascii").strip()
        except OSError as e:
            raise EtapeEchec("enrolement", f"jeton illisible ({type(e).__name__})") from e
        infra = self._ex.profil["provision"]["infra"]
        try:
            rep = self.enroleur(jeton, None, self._cle_pub, infra)
        except EnrolementRefuse as e:
            raise EtapeEchec("enrolement", str(e)) from e
        except (OSError, ValueError) as e:                                            # infrastructure injoignable ou réponse invalide : le parcours reprendra ici
            raise EtapeEchec("enrolement", f"infrastructure indisponible ({type(e).__name__})") from e
        etat["enrolement"] = {"client": str(rep.get("client", ""))[:40], "profil": str(rep.get("profil", ""))[:40], "tunnel": rep.get("tunnel")}

    def _tunnel(self, etat: dict):
        try:
            T.monter(etat["enrolement"]["tunnel"], self.cfg.cle_wg, self.cfg.conf_wg, self._ex.profil["provision"]["infra"], self.executeur)
        except (T.TunnelInvalide, T.TunnelErreur) as e:
            raise EtapeEchec("tunnel", str(e)) from e

    def _plan(self, etat: dict) -> Plan:
        profil = self._ex.profil["services"]["profil"]
        if profil not in PROFILS_PAQUET:
            raise EtapeEchec("plan", f"profil {profil!r} : lite, isp ou full seulement")
        meta = PROFILS_PAQUET[profil]
        r = self._cmd(["apt-get", "-s", "install", "-y", meta], TIMEOUT_INSTALL_S)
        if r.returncode != 0:
            raise EtapeEchec("plan", "simulation apt refusée : " + (r.stderr or "").strip()[:200])
        paquets = []
        for ligne in (r.stdout or "").splitlines():
            if ligne.startswith("Inst "):
                nom = ligne.split()[1]
                if not _PAQUET.match(nom):
                    raise EtapeEchec("plan", "nom de paquet refusé dans la simulation apt")
                paquets.append(nom)
        etat["plan"] = {"profil": profil, "meta": meta, "paquets": paquets}
        return Plan(profil, self._ex.profil["provision"]["mode"], paquets)

    def _installation(self, etat: dict):
        r = self._cmd(["apt-get", "install", "-y", etat["plan"]["meta"]], TIMEOUT_INSTALL_S)
        if r.returncode != 0:
            raise EtapeEchec("installation", "apt-get install a échoué : " + (r.stderr or "").strip()[:200])

    def _application(self, etat: dict):
        for argv in (["premier-pasctl", "appliquer", "--profil", str(self.cfg.reponses)], ["secubox-profilectl", "apply", etat["plan"]["profil"], "--yes"]):
            r = self._cmd(argv, TIMEOUT_INSTALL_S)
            if r.returncode != 0:
                raise EtapeEchec("application", f"{argv[0]} a échoué : " + (r.stderr or "").strip()[:200])

    def _rapporte(self, etape: str, faites: int, termine: bool) -> None:
        if self.rapporteur is None:
            return
        try:
            self.rapporteur(etape, faites, len(ETAPES), termine)
        except (OSError, ValueError):
            pass                                                                    # le tunnel n'est pas toujours monté : la progression est un confort, pas une condition

    # ── boucle ───────────────────────────────────────────────────────────────────────────────────────────────
    def run(self) -> Resultat:
        etat = self._etat()
        if etat.get("fait"):
            return Resultat(True)
        etat.setdefault("debut", int(self._horloge()))
        try:
            self._reponses()                                                 # toujours relu : le fichier peut avoir changé entre deux passages
            if "reponses" not in etat.setdefault("faites", []):
                etat["faites"].insert(0, "reponses")
            plan = None
            for etape in ETAPES[1:]:
                if etape in etat.get("faites", []):
                    if etape == "plan":
                        plan = Plan(etat["plan"]["profil"], self._ex.profil["provision"]["mode"], etat["plan"]["paquets"])
                    continue
                if etape == "cle":
                    self._cle()
                elif etape == "enrolement":
                    self._cle_pub = self._cle_pub or T.assurer_cle(self.cfg.cle_wg, executeur=self.executeur)
                    self._enrolement(etat)
                elif etape == "tunnel":
                    self._tunnel(etat)
                elif etape == "plan":
                    plan = self._plan(etat)
                elif etape == "validation":
                    valideur = self.valideur or (self.fabrique_valideur(self._ex.profil) if self.fabrique_valideur else _refus_par_defaut)
                    if not valideur(plan):
                        raise EtapeEchec("validation", "plan non validé : rien n'est installé")
                elif etape == "installation":
                    self._installation(etat)
                elif etape == "application":
                    self._application(etat)
                self._note(etat, etape)
                self._rapporte(etape, len(etat["faites"]), False)
        except EtapeEchec as e:
            etat["erreur"] = {"etape": e.etape, "detail": e.detail}
            _ecrit_prive(self.cfg.etat, json.dumps(etat, ensure_ascii=False, indent=1))
            return Resultat(False, e.etape, e.detail)
        etat.pop("erreur", None)
        etat["fait"] = True
        _ecrit_prive(self.cfg.etat, json.dumps(etat, ensure_ascii=False, indent=1))
        self._rapporte("application", len(ETAPES), True)
        rap = {"client": etat["enrolement"]["client"], "profil": etat["plan"]["profil"], "paquets": etat["plan"]["paquets"], "domaine": self._ex.profil["reseau"].get("domaine", ""),
               "comptes": ["admin"], "tunnel_adresse": etat["enrolement"]["tunnel"]["adresse"], "debut": etat["debut"], "fin": max(etat["debut"], int(self._horloge())),
               "etapes": list(ETAPES)}
        _ecrit_prive(self.cfg.rapport, json.dumps(rap, ensure_ascii=False, indent=1))
        if self.diffuseur is not None:
            try:
                self.diffuseur(rap)
            except (OSError, ValueError):
                pass                                                                # le rapport reste sur la box ; l'infrastructure l'aura au prochain essai
        return Resultat(True)
