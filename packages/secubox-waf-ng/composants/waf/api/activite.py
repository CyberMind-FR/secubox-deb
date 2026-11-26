# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Activité des campagnes sur 7 jours, par tranche de 6 h (#3969) : agrégat incrémental tenu en tâche de fond.

Même patron que les dossiers par site (#3963, dossiers.py) : un curseur suit le journal des menaces, seuls les octets
neufs sont lus (passe bornée), le lot entier ou rien, état écrit par remplacement atomique. Le suivi du journal
(rotation, troncature, retard, saut) est celui de `dossiers.Agregateur`, hérité tel quel.

Une ligne compte pour une campagne si son adresse est dans l'instantané du corrélateur (campaigns.json) au moment où
elle est lue ; une campagne n'est comptée qu'à partir de la tranche qui suit le moment où elle est connue (`connues`) : avant, sa tranche
est « non mesurée » (null), jamais 0. Une tranche sans couverture du journal est null ; couverte en partie, c'est un
minimum et elle est signalée. Tranches de 6 h alignées sur l'heure de Paris (0, 6, 12, 18 h). Aucune adresse n'est
gardée dans l'état ni rendue : seulement des signatures et des comptes."""
import json
import logging
import math
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from api import dossiers as _d, populations as _populations
except ImportError:  # standalone
    import dossiers as _d
    import populations as _populations

log = logging.getLogger("secubox.waf.activite")

VERSION = 1
PAS = 6 * 3600
TRANCHES = 28                     # 7 jours
MAX_SIGS = 200                    # campagnes suivies
MAX_ADRESSES = 100_000            # adresses de l'index, toutes campagnes
MAX_PAR_CAMPAGNE = 5000
TOLERANCE_MIN = 30                # minutes manquantes tolérées dans une tranche « complète »
PERIODE_S = _d.PERIODE_S
ECRITURE_S = _d.ECRITURE_S
_SIG = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_CLE = re.compile(r"^[0-9]{1,8}$")

CHEMINS: Dict[str, Path] = {
    "journal": Path("/var/log/secubox/waf/waf-threats.log"),
    "etat": Path("/var/lib/secubox/waf/activite-campagnes.json"),
    "campagnes": Path("/var/cache/secubox/waf/campaigns.json"),
    "vie": Path("/var/cache/secubox/waf/nft-etat.json"),
}


def configurer(**chemins: Any) -> None:
    CHEMINS.update({k: Path(v) for k, v in chemins.items()})


def _neuf() -> Dict[str, Any]:
    return {"v": VERSION, "curseur": None, "tete": None, "lus": [], "couverture_depuis": None, "dernier_ts": None,
            "pont": None, "vu": None, "initial": True, "rattrapage": False, "couv": {}, "t": {}, "connues": {},
            "sauts": [], "illisibles": 0, "hors_plafond": 0, "trous": 0}


def _nat(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 52


def _valide(e: Any) -> bool:
    if not (isinstance(e, dict) and e.get("v") == VERSION and set(_neuf()) <= set(e) <= set(_neuf()) | {"lu", "genere_le"}):
        return False
    if any(not isinstance(e[k], dict) for k in ("couv", "t", "connues")) or any(not isinstance(e[k], bool) for k in ("initial", "rattrapage")):
        return False
    if any(e[k] is not None and not _nat(e[k]) for k in ("couverture_depuis", "dernier_ts", "pont", "vu")):
        return False
    if not all(_nat(e[k]) for k in ("illisibles", "hors_plafond", "trous")) or not _nat(e.get("genere_le", 0)):
        return False
    if e["curseur"] is not None and not (isinstance(e["curseur"], str) and _d._veille.RE_POSITION.fullmatch(e["curseur"])):
        return False
    if e["tete"] is not None and not (isinstance(e["tete"], str) and _d._TETE.match(e["tete"])):
        return False
    if not (isinstance(e["lus"], list) and len(e["lus"]) <= _d.MAX_LUS and all(isinstance(x, str) and _d._TETE.match(x) for x in e["lus"])):
        return False
    if not (isinstance(e["sauts"], list) and len(e["sauts"]) <= _d.MAX_SAUTS and all(map(_nat, e["sauts"]))):
        return False
    if not all(_CLE.match(h) and isinstance(m, int) and not isinstance(m, bool) and 0 <= m < 1 << 60 for h, m in e["couv"].items()):
        return False
    if not (len(e["connues"]) <= MAX_SIGS and all(_SIG.match(s) and _nat(v) for s, v in e["connues"].items())):
        return False
    return all(_CLE.match(k) and isinstance(d, dict) and len(d) <= MAX_SIGS and all(_SIG.match(s) and _nat(n) for s, n in d.items())
               for k, d in e["t"].items())


def lire_etat(chemin: Path) -> Dict[str, Any]:
    e = _d._json(chemin)
    return {k: e[k] for k in _neuf()} if _valide(e) else _neuf()


def _decalage(t: float) -> float:
    return datetime.fromtimestamp(t, _d.PARIS).utcoffset().total_seconds()


def tranche(t: float) -> int:
    """Numéro de la tranche de 6 h (heure de Paris) qui contient t."""
    return int((t + _decalage(t)) // PAS)


def debut(k: int) -> int:
    """Instant (UTC) où commence la tranche k."""
    approx = k * PAS
    return int(approx - _decalage(approx - _decalage(approx)))


def lire_index(chemin: Path) -> Dict[str, str]:
    """adresse → signature, depuis l'instantané du corrélateur ; borné. Rien de lisible : index vide."""
    d = _d._json(chemin)
    idx: Dict[str, str] = {}
    camps = d.get("campagnes") if isinstance(d, dict) else None
    if not isinstance(camps, list):
        return idx
    for c in camps[:MAX_SIGS]:
        sig = c.get("signature") if isinstance(c, dict) else None
        ips = c.get("attaquants") if isinstance(c, dict) else None
        if not (isinstance(sig, str) and _SIG.match(sig) and isinstance(ips, list)):
            continue
        for ip in ips[:MAX_PAR_CAMPAGNE]:
            if isinstance(ip, str) and len(idx) < MAX_ADRESSES:
                idx.setdefault(ip, sig)
    return idx


class Activite(_d.Agregateur):
    """Compteurs signature × tranche de 6 h, bornés à MAX_SIGS signatures par tranche, sur 7 jours."""

    def __init__(self, etat: Optional[Dict[str, Any]] = None, index: Optional[Dict[str, str]] = None):
        self.e = etat if isinstance(etat, dict) and "t" in etat else _neuf()   # dossiers réinitialise avec son propre état
        if index is not None or not hasattr(self, "index"):
            self.index = index or {}

    def copie(self) -> "Activite":
        return Activite(json.loads(json.dumps(self.e)), self.index)

    def connaitre(self, maintenant: float) -> None:
        """Signatures nouvellement connues : comptées à partir d'ici (au premier départ, depuis le début de la reprise)."""
        sigs = set(self.index.values())
        premier = self.e["curseur"] is None
        for s in sorted(sigs):
            if s not in self.e["connues"] and len(self.e["connues"]) < MAX_SIGS:
                self.e["connues"][s] = 0 if premier else int(self.e["dernier_ts"] or maintenant)
        for s in [s for s in self.e["connues"] if s not in sigs]:
            del self.e["connues"][s]

    def _ajouter(self, ligne: Any, servis: Any, maintenant: float) -> None:
        t = _populations._horodatage(ligne.get("timestamp")) if isinstance(ligne, dict) else None
        if t is None or not math.isfinite(t) or t > maintenant + 300:
            self.e["illisibles"] += 1
            return
        t = min(t, maintenant)
        if tranche(t) <= tranche(maintenant) - TRANCHES:
            return
        pont = self.e["pont"]
        self.couvrir(pont if pont is not None and 0 <= t - pont <= _d.PONT_S else t, t)
        self.e["pont"] = max(int(t), pont or 0)
        self.e["dernier_ts"] = max(int(t), self.e["dernier_ts"] or 0)
        cat = ligne.get("category")
        cat = cat if isinstance(cat, str) else ""
        if ligne.get("severity") == "audit" or cat.startswith(("multipart-", "body-inspect-")):
            return                                    # ligne d'état, pas une requête hostile
        sig = self.index.get(ligne.get("client_ip")) if isinstance(ligne.get("client_ip"), str) else None
        if sig is None or sig not in self.e["connues"]:
            return
        d = self.e["t"].setdefault(str(tranche(t)), {})
        if sig not in d and len(d) >= MAX_SIGS:
            self.e["hors_plafond"] += 1
            return
        d[sig] = d.get(sig, 0) + 1

    def purger(self, maintenant: float) -> None:
        seuil = tranche(maintenant) - TRANCHES
        for k in [k for k in self.e["t"] if int(k) <= seuil]:
            del self.e["t"][k]
        h0 = (debut(seuil + 1)) // 3600
        for k in [k for k in self.e["couv"] if int(k) < h0]:
            del self.e["couv"][k]
        self.e["sauts"] = [x for x in self.e["sauts"] if x > maintenant - TRANCHES * PAS][-_d.MAX_SAUTS:]


def construire(e: Dict[str, Any], maintenant: float, lu: bool) -> Dict[str, Any]:
    """La vue rendue : début de chaque tranche, sa couverture, et la série de chaque campagne (null = non mesuré)."""
    a = Activite(e)
    fin = tranche(maintenant)
    ks = list(range(fin - TRANCHES + 1, fin + 1))
    debuts, couverture = [], []
    for k in ks:
        d0, d1 = debut(k), min(debut(k + 1), int(maintenant))
        attendu = max(1, (d1 - d0) // 60)
        vues = sum(a.minutes(h) for h in range(d0 // 3600, (debut(k + 1) - 1) // 3600 + 1))
        debuts.append(d0)
        couverture.append(None if vues == 0 else "complete" if vues >= attendu - TOLERANCE_MIN else "partielle")
    camps = {}
    for sig, depuis in e["connues"].items():
        serie: List[Optional[int]] = []
        for i, k in enumerate(ks):
            if couverture[i] is None or debut(k) < depuis:     # connue en cours de tranche : tranche incomplète, non mesurée
                serie.append(None)
            else:
                serie.append(e["t"].get(str(k), {}).get(sig, 0))
        camps[sig] = serie
    return {"disponible": True, "genere_le": int(maintenant), "pas_s": PAS, "debuts": debuts, "couverture": couverture,
            "couverture_depuis": e["couverture_depuis"], "lu": lu, "trous": e["trous"], "hors_plafond": e["hors_plafond"],
            "campagnes": camps}


_fond: Dict[str, Any] = {"agregat": None, "vue": None, "ecrit": 0.0}
_verrou = threading.Lock()
_passe = threading.Lock()
_relu: Dict[str, Any] = {"cle": None, "vue": None}


def rafraichir(maintenant: Optional[float] = None, forcer: bool = False) -> Dict[str, Any]:
    """Une passe (tâche de fond seulement)."""
    t = time.time() if maintenant is None else maintenant
    with _passe:
        a = _fond["agregat"]
        if a is None:
            a = Activite(lire_etat(CHEMINS["etat"]))
            a.e["initial"] = True
        a = a.copie()
        a.index = lire_index(CHEMINS["campagnes"])
        a.connaitre(t)
        lu = a.suivre(CHEMINS["journal"], None, t)
        if lu:
            try:
                vie = -60 <= t - CHEMINS["vie"].stat().st_mtime <= _d.VIE_MOTEUR_S
            except OSError:
                vie = False
            a.vivant(t, vie)
        a.purger(t)
        vue = construire(a.e, t, lu)
        _fond["agregat"] = a
        with _verrou:
            _fond["vue"] = vue
        if forcer or t - _fond["ecrit"] >= ECRITURE_S or t < _fond["ecrit"]:
            if _d.ecrire_etat(CHEMINS["etat"], {**a.e, "lu": lu, "genere_le": int(t)}):
                _fond["ecrit"] = t
        return vue


def vider() -> None:
    with _verrou:
        _fond.update(agregat=None, vue=None, ecrit=0.0)
        _relu.update(cle=None, vue=None)


def vue(maintenant=time.time) -> Dict[str, Any]:
    """Vue de la tâche de fond ; ailleurs (agrégateur), celle du fichier d'état. Rien de mesuré : disponible False."""
    with _verrou:
        v = _fond["vue"]
    if v is None:
        try:
            st = CHEMINS["etat"].stat()
        except OSError:
            return {"disponible": False}
        cle = (st.st_mtime_ns, st.st_ino, st.st_size)
        with _verrou:
            if _relu["cle"] == cle:
                v = _relu["vue"]
        if v is None or _relu["cle"] != cle:
            brut = _d._json(CHEMINS["etat"])
            v = construire({k: brut[k] for k in _neuf()}, float(brut["genere_le"]), bool(brut.get("lu"))) \
                if _valide(brut) and _nat(brut.get("genere_le")) and brut.get("genere_le") else None
            with _verrou:
                _relu.update(cle=cle, vue=v)
    if v is None:
        return {"disponible": False}
    return {**v, "age_s": max(0, int(maintenant() - v["genere_le"]))}
