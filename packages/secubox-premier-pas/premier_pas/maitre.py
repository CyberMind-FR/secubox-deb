# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: Premier Pas — le PANNEAU MAÎTRE (#1522, couche 4)
CyberMind — https://cybermind.fr

Sur une box en service (gk2), l'administrateur prépare le profil d'une future
box : il l'enregistre ici, l'exporte (clé USB « SBXPROFIL », /boot/secubox/,
microSD) ou le POUSSE à distance à la box neuve, étape par étape, par la même
API que son kiosque — avec le code de démarrage que la box neuve affiche sur
son écran (l'accès physique reste la preuve).

Le maître ne garde JAMAIS de mot de passe en clair : il hache à la saisie, et
pousse l'empreinte (champ « empreinte » de l'étape admin).
"""
from __future__ import annotations

import ipaddress
import os
import re
import time
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import profil as P
from . import remplir as R

_NOM = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
ORDRE_POUSSEE = ("bienvenue", "nom", "horloge", "admin", "reseau", "services", "maillage", "majs")


def dossier() -> Path:
    return Path(os.environ.get("PREMIER_PAS_MAITRE_DIR", "/var/lib/secubox/premier-pas/maitre"))


def _chemin(nom: str) -> Path:
    if not _NOM.match(nom or ""):
        raise R.Refus("Nom de box : minuscules, chiffres et tirets.")
    return dossier() / f"{nom}.toml"


def liste() -> List[Dict[str, Any]]:
    out = []
    for f in sorted(dossier().glob("*.toml")) if dossier().is_dir() else []:
        try:
            prof = tomllib.loads(f.read_text())
        except (OSError, ValueError):
            continue
        ex = P.examine(prof)
        out.append({"nom": f.stem, "complet": ex.complet, "reprendre": P.LIBELLES[ex.premiere_etape],
                    "erreurs": ex.erreurs, "modifie": int(f.stat().st_mtime), "profil": R.vue(prof)})
    return out


def lit(nom: str) -> Dict[str, Any]:
    try:
        return tomllib.loads(_chemin(nom).read_text())
    except OSError:
        raise R.Refus("Profil inconnu.")


def enregistre(nom: str, profil: Dict[str, Any]) -> Dict[str, Any]:
    """Enregistre un profil préparé. `admin.mot_de_passe` + `confirmation` en
    clair est haché ici ; « demander » ou une empreinte sont gardés tels quels ;
    absent = on garde l'empreinte déjà enregistrée."""
    ancien: Dict[str, Any] = {}
    try:
        ancien = lit(nom)
    except R.Refus:
        pass
    propre: Dict[str, Any] = {}
    for section in ("box", "reseau", "services", "maillage", "apt"):
        if isinstance(profil.get(section), dict):
            propre[section] = {k: v for k, v in profil[section].items() if v not in (None, "")}
    propre.setdefault("box", {})["nom"] = nom
    admin = profil.get("admin") or {}
    mdp = admin.get("mot_de_passe")
    if mdp and mdp not in ("demander", "défini") and not P._ARGON2.match(str(mdp)):
        empreinte = R.hache_mdp(str(mdp), str(admin.get("confirmation", "")))
    elif mdp == "demander" or (P._ARGON2.match(str(mdp or ""))):
        empreinte = mdp
    else:
        empreinte = (ancien.get("admin") or {}).get("mot_de_passe", "demander")
    propre["admin"] = {"mot_de_passe": empreinte, "totp": "enroler"}
    if (propre.get("reseau") or {}).get("mode") == "lan":
        propre["reseau"].pop("domaine", None)
    m = propre.get("maillage") or {}
    if m.get("mode") != "rejoindre":
        m.pop("rejoindre", None)
        m.pop("jeton", None)
    elif not m.get("jeton") and (ancien.get("maillage") or {}).get("jeton"):
        m["jeton"] = ancien["maillage"]["jeton"]           # « défini » dans la vue
    dossier().mkdir(parents=True, exist_ok=True)
    f = _chemin(nom)
    tmp = f.with_suffix(".tmp")
    tmp.write_text(texte(propre))
    os.chmod(tmp, 0o640)
    os.replace(tmp, f)
    ex = P.examine(propre)
    return {"nom": nom, "complet": ex.complet, "reprendre": P.LIBELLES[ex.premiere_etape],
            "erreurs": ex.erreurs, "profil": R.vue(propre)}


def supprime(nom: str) -> None:
    _chemin(nom).unlink(missing_ok=True)


def texte(profil: Dict[str, Any]) -> str:
    """Le profil prêt à poser en /boot/secubox/profil.toml ou sur SBXPROFIL."""
    lignes = [f"# Profil SecuBox Premier Pas — préparé sur la box maîtresse le {time.strftime('%Y-%m-%d %H:%M')}",
              "# À poser en /boot/secubox/profil.toml, ou sur une clé USB nommée SBXPROFIL.",
              "# Contient l'empreinte (pas le clair) du mot de passe admin, et le jeton",
              "# d'invitation au maillage s'il y en a un : à traiter comme un secret."]
    for section in ("box", "admin", "reseau", "services", "maillage", "apt"):
        bloc = profil.get(section)
        if bloc:
            lignes += ["", f"[{section}]"] + [f"{k} = {R._toml_val(v)}" for k, v in bloc.items() if v is not None]
    return "\n".join(lignes) + "\n"


# ── Pousser à distance ─────────────────────────────────────────────────────

def adresse_permise(adresse: str) -> str:
    """Seulement une box du réseau local ou du maillage : jamais Internet (le
    maître ne doit pas devenir un relais vers n'importe où)."""
    try:
        ip = ipaddress.ip_address(adresse.strip())
    except ValueError:
        raise R.Refus("Adresse : une IPv4 du réseau local ou du maillage.")
    if ip.version != 4 or not ip.is_private or ip.is_loopback:
        raise R.Refus("Adresse : une IPv4 du réseau local ou du maillage.")
    return str(ip)


def _valeurs_etape(profil: Dict[str, Any], etape: str) -> Optional[Dict[str, Any]]:
    b, r = profil.get("box") or {}, profil.get("reseau") or {}
    m, a, ad = profil.get("maillage") or {}, profil.get("apt") or {}, profil.get("admin") or {}
    if etape == "bienvenue":
        return {"langue": b.get("langue", "fr"), "clavier": b.get("clavier", "fr")}
    if etape == "nom":
        return {"nom": b["nom"]} if b.get("nom") else None
    if etape == "horloge":
        return {"fuseau": b["fuseau"], "ntp": True} if b.get("fuseau") else None
    if etape == "admin":
        mdp = ad.get("mot_de_passe")
        return {"empreinte": mdp} if mdp and P._ARGON2.match(str(mdp)) else None
    if etape == "reseau":
        return {k: r[k] for k in ("mode", "domaine") if k in r} or None
    if etape == "services":
        return {"profil": profile} if (profile := (profil.get("services") or {}).get("profil")) else None
    if etape == "maillage":
        return {k: m[k] for k in ("mode", "rejoindre", "jeton") if k in m} or None
    if etape == "majs":
        return {k: a[k] for k in ("auto", "heure") if k in a} if "auto" in a else None
    return None


def _mes_adresses() -> List[str]:
    import json as _j, subprocess  # noqa: PLC0415
    try:
        r = subprocess.run(["ip", "-j", "-4", "addr"], capture_output=True, text=True, timeout=5)
        return [a["local"] for i in _j.loads(r.stdout or "[]") for a in i.get("addr_info", [])]
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return []


def _ip_vers(adresse: str) -> Optional[str]:
    """L'adresse de CETTE box que la box neuve voit (route réelle, rien n'est envoyé)."""
    import socket  # noqa: PLC0415
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((adresse, 9))
            return s.getsockname()[0]
    except OSError:
        return None


def rejoindre_joignable(rejoindre: str, adresse: str, mes_adresses=None, ip_vers=None) -> str:
    """L'invitation de secubox-p2p annonce l'adresse que préfère get_lan_ip()
    — 192.168.255.x, l'ancien maillage OpenWrt — que la box neuve ne joint
    pas depuis le LAN (vu sur gk3, #1544). Si la cible est l'une des adresses
    du maître, on la remplace par celle qu'il utilise pour joindre la box."""
    mes = _mes_adresses() if mes_adresses is None else mes_adresses
    if rejoindre not in mes:
        return rejoindre
    vue = (ip_vers or _ip_vers)(adresse)
    return vue or rejoindre


def pousse(nom: str, adresse: str, code: str, mode: str = "proposer", client=None, par: str = "") -> Dict[str, Any]:
    """Remplit la box neuve étape par étape, puis la PROPOSE (l'utilisateur
    valide à l'écran) ou la FORCE (application immédiate, alerte à l'écran).
    S'arrête au premier refus, et dit lequel."""
    if mode not in ("proposer", "forcer", "remplir"):
        raise R.Refus("Mode : proposer, forcer ou remplir.")
    adresse = adresse_permise(adresse)
    # Espaces seulement : l'écran groupe le code par espaces. Surtout pas les
    # tirets — le jeton est du base64 « urlsafe », qui en contient.
    code = "".join((code or "").split())
    if not code:
        raise R.Refus("Code de démarrage : celui qu'affiche l'écran de la box neuve.")
    profil = lit(nom)
    if client is None:
        import httpx  # noqa: PLC0415
        # La box neuve a un certificat auto-signé : réseau local ou maillage seulement (ci-dessus).
        client = httpx.Client(verify=False, timeout=30)
    base = f"https://{adresse}/api/v1/premier-pas"
    h = {"X-Premier-Pas": code}
    faites: List[str] = []
    for etape in ORDRE_POUSSEE:
        v = _valeurs_etape(profil, etape)
        if v is None:
            continue
        if etape == "maillage" and v.get("rejoindre"):
            v["rejoindre"] = rejoindre_joignable(str(v["rejoindre"]), adresse)
        r = client.put(f"{base}/etape/{etape}", json=v, headers=h)
        if r.status_code != 200:
            try:
                detail = r.json().get("detail")
            except Exception:  # noqa: BLE001
                detail = r.text[:200]
            return {"ok": False, "faites": faites, "arret": P.LIBELLES[etape], "detail": detail, "code": r.status_code}
        faites.append(P.LIBELLES[etape])
    etat = client.get(f"{base}/etat").json()
    res = {"ok": True, "faites": faites, "complet": etat.get("complet"), "reprendre": etat.get("reprendre")}
    if mode != "remplir":
        import socket  # noqa: PLC0415
        r = client.post(f"{base}/proposition", headers=h,
                        json={"par": par or socket.gethostname(), "mode": mode})
        try:
            corps = r.json()
        except Exception:  # noqa: BLE001
            corps = {}
        res["proposition"] = corps if r.status_code == 200 else {"erreur": corps.get("detail", r.status_code)}
    return res


def distant(adresse: str, client=None) -> Dict[str, Any]:
    """L'état de la box neuve (lecture publique de son API), pour suivre."""
    adresse = adresse_permise(adresse)
    if client is None:
        import httpx  # noqa: PLC0415
        client = httpx.Client(verify=False, timeout=15)
    return client.get(f"https://{adresse}/api/v1/premier-pas/etat").json()
