# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: ad-guard :: routes `/adblock-tv/protection/dpi/*` du lot 4 SBX TV PRIVACY (#3374) — DPI par appareil.

Gardes : `/protection/dpi/etat` en `require_lecture_nominative` (le porteur délégué n'y voit que noms et couverture, ni MAC ni forçage) ;
toute donnée par appareil (applications, flux, découvertes, coupures) et la reprise de nDPId en `require_jwt` (administrateur réel).
Aucune route d'usager. Lecture seule de `dpi-appareils.db` et `etat-dpi.json`, écrits par le moteur.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

try:
    from . import dnstv, dnstv_contournement, dnstv_dpi, dnstv_taxonomie
    from . import dnstv_routes as _r
except ImportError:                                  # lancé hors paquet
    from api import dnstv, dnstv_contournement, dnstv_dpi, dnstv_taxonomie
    from api import dnstv_routes as _r

from secubox_core.auth import require_jwt

router = APIRouter(prefix="/adblock-tv", tags=["adblock-tv-dpi"])

FENETRES = {"1h": 3600, "24h": 86400, "7j": 7 * 86400}
MAC_MOTIF = r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
NOTE_FORCAGE = ("forçage DNS posé, effectif seulement si les flux de l'appareil traversent gk2 (mode LAN) ; sur un LAN plat la TV "
                "joint la Freebox directement")
TypeDecouverte = Literal["repli", "repli-protege", "secours", "sans-dns", "dns-chiffre", "contournement"]


def _admin(lecteur) -> bool:
    return isinstance(lecteur, dict) and not lecteur.get("tableau_de_bord") and bool(_r.est_admin_reel(lecteur))


def _magasin() -> dnstv_dpi.MagasinDPI:
    return dnstv_dpi.MagasinDPI(dnstv.DOSSIER_ETAT / "dpi-appareils.db", lecture_seule=True)     # I1 : l'API ne crée ni n'écrit


def _motifs():
    return dnstv_dpi.charger_motifs_ssai(dnstv.DOSSIER_LISTES / "ssai.txt")


def _etat_tv() -> dict:
    etat, erreur = dnstv.lire_etat()
    if erreur:
        raise HTTPException(503, "état illisible")
    return etat


def _suspendus() -> set:
    f = dnstv.DOSSIER_ETAT / dnstv_contournement.FICHIER_SUSPENSIONS
    try:
        return dnstv_contournement.lire_suspensions(f.read_text(encoding="utf-8"), int(time.time())) if f.is_file() else set()
    except OSError:
        return set()


def _verbe(verbe: str) -> dict:
    """Verbe exact du contrôleur root (sudoers)."""
    argv = ["sudo", "-n", _r.CTL, verbe] if os.geteuid() != 0 else [_r.CTL, verbe]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise HTTPException(502, f"contrôleur injoignable ({type(e).__name__})") from e
    if r.returncode != 0:
        raise HTTPException(502, ((r.stderr or r.stdout).strip() or "contrôleur en échec")[:300])
    try:
        return json.loads(r.stdout or "{}")
    except ValueError:
        return {}


@router.get("/protection/dpi/etat")
def etat_dpi(lecteur=Depends(_r.require_lecture_nominative)):
    """Disponibilité des sources, couverture par appareil (« dns » = DNS seulement, « dns+dpi »), pause de charge, forçage du DNS."""
    e = dnstv_dpi.lire_etat_dpi()
    if e is None:
        return {"disponible": False, "raison": "absent", "appareils": []}
    age = int(time.time()) - int(e.get("genere", 0))
    admin = _admin(lecteur)
    forces, susp = set(), set()
    if admin:
        susp = _suspendus()
        forces = set(dnstv_contournement.forces(_etat_tv(), susp))
    appareils = []
    for a in e.get("appareils", []):
        if admin:
            appareils.append(dict(a, forcage={"pose": a["mac"] in forces, "suspendu": a["mac"] in susp, "note": NOTE_FORCAGE}))
        else:
            appareils.append({"nom": a.get("nom"), "couverture": a.get("couverture")})
    return {"disponible": age <= 600, "raison": None if age <= 600 else "perime", "age_s": age, "sources": e.get("sources", {}),
            "pause_charge": (e.get("charge") or {}).get("pause"), "appareils": appareils}


@router.get("/protection/dpi/applications")
def applications(mac: str = Query(..., pattern=MAC_MOTIF), fenetre: Literal["1h", "24h", "7j"] = "24h",
                 limite: int = Query(50, ge=1, le=200), _=Depends(require_jwt)):
    """Applications nDPI d'un appareil, triées par volume : hôtes, badges `sans_dns`, `dns_chiffre`, `ssai` et catégorie de l'hôte."""
    motifs = _motifs()
    taxo = dnstv_taxonomie.Taxonomie.depuis_dossier()
    out = []
    for a in _magasin().applications(mac, int(time.time()) - FENETRES[fenetre], limite):
        a["ssai"] = any(dnstv_dpi.est_ssai(h, motifs) for h in a["hotes"])
        a["categorie"] = taxo.classer(a["hotes"][0])["categorie"] if a["hotes"] else "INCONNU"
        out.append(a)
    return {"mac": mac, "fenetre": fenetre, "applications": out}


@router.get("/protection/dpi/flux")
def flux(mac: str = Query(..., pattern=MAC_MOTIF), appli: Optional[str] = Query(None, pattern=r"^[A-Za-z0-9._-]{1,48}$"),
         fenetre: Literal["1h", "24h", "7j"] = "24h", decalage: int = Query(0, ge=0, le=100000), limite: int = Query(50, ge=1, le=200),
         _=Depends(require_jwt)):
    total, lignes = _magasin().lignes_flux(mac, int(time.time()) - FENETRES[fenetre], appli, decalage, limite)
    return {"total": total, "lignes": lignes}


@router.get("/protection/dpi/decouvertes")
def decouvertes(depuis: int = Query(0, ge=0), type: Optional[TypeDecouverte] = None,  # noqa: A002 — nom d'API stable (lot 5b)
                mac: Optional[str] = Query(None, pattern=MAC_MOTIF), limite: int = Query(100, ge=1, le=500), _=Depends(require_jwt)):
    """Interface du lot 5b : identifiant croissant, champs stables, `etat` ∈ nouvelle | candidat | ecartee-protegee."""
    noms = {c.get("mac"): c["nom"] for c in _etat_tv().get("clients", []) if c.get("mac")}
    motifs = _motifs()
    out = []
    for d in _magasin().decouvertes(depuis, type, mac, limite):
        d["appareil"] = noms.get(d["mac"], "")
        d["ssai"] = dnstv_dpi.est_ssai(d["domaine"], motifs)
        if d["type"] == "repli-protege":
            d["etat"] = "ecartee-protegee"
        out.append(d)
    return {"decouvertes": out, "dernier_id": out[-1]["id"] if out else depuis}


@router.get("/protection/dpi/coupures")
def coupures(mac: str = Query(..., pattern=MAC_MOTIF), fenetre: Literal["1h", "24h"] = "1h", _=Depends(require_jwt)):
    """Frise : chaque refus publicitaire et ce qui apparaît dans les 30 s (DNS), SSAI marqué."""
    etat = _etat_tv()
    adresses = {c["ip"] for c in etat.get("clients", []) if c.get("mac") == mac}
    if adresses:                                     # m3 : toutes les adresses de la MAC (mémoire de 24 h du moteur), IPv6 comprises
        maintenant = int(time.time())
        adresses |= {a for a, (m, vu) in _magasin().charger_voisins().items() if m == mac and maintenant - vu <= dnstv_dpi.MEMOIRE_VOISINS_S}
    adresses = sorted(adresses)
    if not adresses:
        raise HTTPException(404, "appareil inconnu")
    taxo = dnstv_taxonomie.Taxonomie.depuis_dossier()
    evts = dnstv.Magasin(dnstv.DOSSIER_ETAT / "dnstv.db").evenements(adresses, int(time.time()) - FENETRES[fenetre])
    return {"mac": mac, "coupures": dnstv_dpi.frise(evts, lambda d: taxo.classer(d)["categorie"], _motifs())[:50]}


@router.post("/protection/dpi/reprendre")
def reprendre(_=Depends(require_jwt)):
    """Reprise MANUELLE de nDPId après une pause de charge (verbe root audité)."""
    return dnstv_dpi.reprendre_manuellement(lambda v: type("R", (), {"returncode": 0 if _verbe(v).get("ok", True) else 1})())
