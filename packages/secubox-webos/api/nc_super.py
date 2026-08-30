# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: WebOS — Nextcloud « Super Cardlet », côté serveur.

Le broker (`acces.py`) garde le mot de passe d'application DANS la box : cette
couche lit et AGIT sur le Nextcloud de la personne EN SON NOM, et ne rend à la
carte que des titres, des chiffres et le résultat de ses propres actions —
jamais la clé. Tout passe par `acces.secret_de(qui,'nextcloud')` (usage serveur).

Capacités (choix utilisateur) :
  • quota + activité  — l'en-tête « super » (OCS).
  • fichiers          — navigateur WebDAV (PROPFIND, récents en tête).
  • partages          — liste OCS + création d'un lien public.
  • actions gérables  — partager (lien), supprimer, téléverser.

Aucune exception ne remonte telle quelle : son texte peut contenir l'URL, donc
la clé. On renvoie une raison courte et typée, jamais le détail brut.
"""
from __future__ import annotations

import email.utils
import xml.etree.ElementTree as ET
from urllib.parse import quote
from typing import Any, Optional

import httpx

from . import acces

_DAV = "DAV:"
_OC = "http://owncloud.org/ns"
_NS = {"d": _DAV, "oc": _OC}


def _ctx(qui: str) -> Optional[tuple[str, str, tuple[str, str]]]:
    """(hôte, compte, auth Basic) pour cette personne — ou None sans accès."""
    d = acces.secret_de(qui, "nextcloud")
    if not d or not d.get("secret"):
        return None
    hote = acces.SERVICES.get("nextcloud", {}).get("hote", "")
    return hote, (d.get("compte") or ""), (d.get("compte") or "", d["secret"])


def _vide(detail: str) -> dict:
    return {"ok": False, "detail": detail}


def _segments(chemin: str) -> Optional[list[str]]:
    """Chemin POSIX -> segments, SANS traversée. `..` => None (refus net)."""
    out: list[str] = []
    for seg in (chemin or "/").split("/"):
        seg = seg.strip()
        if seg in ("", "."):
            continue
        if seg == "..":
            return None                 # jamais de remontée hors de la racine
        out.append(seg)
    return out


def _humain(n: Optional[int]) -> str:
    if not isinstance(n, int) or n < 0:
        return ""
    u = ["o", "Ko", "Mo", "Go", "To"]
    x = float(n)
    for s in u:
        if x < 1024 or s == u[-1]:
            return (f"{x:.0f} {s}" if s == "o" or x >= 10 else f"{x:.1f} {s}")
        x /= 1024
    return ""


def _epoch(rfc: str) -> int:
    try:
        return int(email.utils.parsedate_to_datetime(rfc).timestamp())
    except Exception:
        return 0


def _url_dav(hote: str, compte: str, segs: list[str]) -> str:
    base = f"https://{hote}/remote.php/dav/files/{quote(compte)}"
    return base + "".join("/" + quote(s) for s in segs)


# ── Lectures ────────────────────────────────────────────────────────────────

async def tableau(qui: str) -> dict:
    """En-tête « super » : identité, quota (jauge) et activité récente."""
    c = _ctx(qui)
    if not c:
        return _vide("aucun acces")
    hote, compte, auth = c
    quota: dict = {}
    activite: list[dict] = []
    try:
        async with httpx.AsyncClient(verify=False, timeout=12, auth=auth) as cli:
            u = await cli.get(f"https://{hote}/ocs/v2.php/cloud/user",
                              params={"format": "json"},
                              headers={"OCS-APIRequest": "true"})
            if u.status_code == 200:
                qd = (((u.json() or {}).get("ocs") or {}).get("data") or {}).get("quota") or {}
                used, total, free = qd.get("used"), qd.get("total"), qd.get("free")
                pct = qd.get("relative")
                if isinstance(used, int) and isinstance(total, int) and total > 0:
                    quota = {"utilise": used, "total": total, "libre": free if isinstance(free, int) else None,
                             "pct": round(100 * used / total, 1),
                             "utilise_h": _humain(used), "total_h": _humain(total)}
                elif isinstance(pct, (int, float)):
                    quota = {"pct": round(float(pct), 1), "utilise_h": _humain(used) if isinstance(used, int) else ""}
            a = await cli.get(f"https://{hote}/ocs/v2.php/apps/activity/api/v2/activity",
                              params={"format": "json", "limit": 8},
                              headers={"OCS-APIRequest": "true"})
            if a.status_code == 200:
                for x in ((a.json() or {}).get("ocs") or {}).get("data") or []:
                    activite.append({"titre": (x.get("subject") or "")[:160],
                                     "sous": x.get("object_name") or x.get("app") or "",
                                     "quand": x.get("datetime") or "", "url": x.get("link") or ""})
    except Exception as e:
        return _vide("lecture impossible : %s" % type(e).__name__)
    return {"ok": True, "compte": compte, "hote": hote, "quota": quota, "activite": activite}


async def fichiers(qui: str, chemin: str = "/") -> dict:
    """Navigateur WebDAV : contenu d'un dossier (PROPFIND depth 1), dossiers
    d'abord puis fichiers du plus récent au plus ancien. Récents en tête."""
    c = _ctx(qui)
    if not c:
        return _vide("aucun acces")
    hote, compte, auth = c
    segs = _segments(chemin)
    if segs is None:
        return _vide("chemin refuse")
    url = _url_dav(hote, compte, segs) + "/"
    corps = (
        '<?xml version="1.0"?>'
        '<d:propfind xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns"><d:prop>'
        '<d:resourcetype/><d:getlastmodified/><d:getcontentlength/>'
        '<d:getcontenttype/><oc:fileid/></d:prop></d:propfind>'
    )
    try:
        async with httpx.AsyncClient(verify=False, timeout=15, auth=auth) as cli:
            r = await cli.request("PROPFIND", url,
                                  headers={"Depth": "1", "Content-Type": "application/xml"},
                                  content=corps)
    except Exception as e:
        return _vide("lecture impossible : %s" % type(e).__name__)
    if r.status_code == 404:
        return _vide("dossier introuvable")
    if r.status_code in (401, 403):
        return _vide("acces refuse par le cloud")
    if r.status_code >= 400:
        return _vide("cloud: %d" % r.status_code)

    prefixe = "/remote.php/dav/files/%s" % quote(compte)
    moi = prefixe + "".join("/" + quote(s) for s in segs)
    entrees: list[dict] = []
    try:
        root = ET.fromstring(r.content)
    except Exception:
        return _vide("reponse illisible")
    for resp in root.findall("d:response", _NS):
        href = (resp.findtext("d:href", default="", namespaces=_NS) or "").rstrip("/")
        # On saute l'entrée du dossier lui-même.
        if href.rstrip("/") == moi.rstrip("/"):
            continue
        ok200 = resp.find(".//d:propstat[d:status='HTTP/1.1 200 OK']/d:prop", _NS)
        prop = ok200 if ok200 is not None else resp.find(".//d:prop", _NS)
        if prop is None:
            continue
        est_dossier = prop.find("d:resourcetype/d:collection", _NS) is not None
        taille = prop.findtext("d:getcontentlength", default="", namespaces=_NS)
        mod = prop.findtext("d:getlastmodified", default="", namespaces=_NS)
        ctype = prop.findtext("d:getcontenttype", default="", namespaces=_NS)
        fid = prop.findtext("oc:fileid", default="", namespaces=_NS)
        # Nom lisible = dernier segment du href (décodé par ElementTree ? non : href est encodé).
        from urllib.parse import unquote
        nom = unquote(href.split("/")[-1]) if href else ""
        try:
            tn = int(taille) if taille else None
        except ValueError:
            tn = None
        rel = "/" + "/".join(segs + [nom]) if segs else "/" + nom
        entrees.append({
            "nom": nom, "dossier": est_dossier,
            "taille": tn, "taille_h": _humain(tn) if not est_dossier else "",
            "modifie": mod, "ts": _epoch(mod), "type": ctype,
            "chemin": rel,
            # Lien profond d'ouverture dans Nextcloud (par fileid quand connu).
            "vue": (f"https://{hote}/index.php/f/{fid}" if fid else
                    f"https://{hote}/index.php/apps/files/?dir={quote('/' + '/'.join(segs + [nom]))}"),
        })
    entrees.sort(key=lambda e: (0 if e["dossier"] else 1, -(e["ts"] or 0), e["nom"].lower()))
    chemin_norm = "/" + "/".join(segs)
    parent = "/" + "/".join(segs[:-1]) if segs else None
    return {"ok": True, "chemin": chemin_norm, "parent": parent, "compte": compte,
            "hote": hote, "entrees": entrees[:60]}


async def partages(qui: str) -> dict:
    """Partages de la personne (OCS) — liens et partages internes."""
    c = _ctx(qui)
    if not c:
        return _vide("aucun acces")
    hote, compte, auth = c
    try:
        async with httpx.AsyncClient(verify=False, timeout=12, auth=auth) as cli:
            r = await cli.get(f"https://{hote}/ocs/v2.php/apps/files_sharing/api/v1/shares",
                              params={"format": "json"}, headers={"OCS-APIRequest": "true"})
    except Exception as e:
        return _vide("lecture impossible : %s" % type(e).__name__)
    if r.status_code != 200:
        return _vide("partages: %d" % r.status_code)
    ent = []
    for s in (((r.json() or {}).get("ocs") or {}).get("data") or []):
        st = s.get("share_type")
        avec = s.get("share_with_displayname") or s.get("share_with") or ""
        typ = {0: "utilisateur", 1: "groupe", 3: "lien public", 4: "email", 6: "fédéré"}.get(st, str(st))
        ent.append({"id": s.get("id"), "chemin": s.get("path") or "",
                    "nom": (s.get("path") or "").rstrip("/").split("/")[-1] or "/",
                    "type": typ, "public": st == 3, "avec": avec if st != 3 else "",
                    "url": s.get("url") or "", "dossier": s.get("item_type") == "folder"})
    return {"ok": True, "entrees": ent}


# ── Actions gérables ────────────────────────────────────────────────────────

async def partager(qui: str, chemin: str) -> dict:
    """Crée un LIEN PUBLIC (shareType=3) vers un fichier/dossier de la personne."""
    c = _ctx(qui)
    if not c:
        return _vide("aucun acces")
    hote, compte, auth = c
    segs = _segments(chemin)
    if segs is None or not segs:
        return _vide("chemin refuse")
    path = "/" + "/".join(segs)
    try:
        async with httpx.AsyncClient(verify=False, timeout=12, auth=auth) as cli:
            r = await cli.post(f"https://{hote}/ocs/v2.php/apps/files_sharing/api/v1/shares",
                               params={"format": "json"},
                               data={"path": path, "shareType": 3},
                               headers={"OCS-APIRequest": "true"})
    except Exception as e:
        return _vide("action impossible : %s" % type(e).__name__)
    if r.status_code not in (200, 201):
        return _vide("partage refuse (%d)" % r.status_code)
    data = (((r.json() or {}).get("ocs") or {}).get("data") or {})
    return {"ok": True, "url": data.get("url") or "", "id": data.get("id")}


async def supprimer(qui: str, chemin: str) -> dict:
    """Supprime un fichier/dossier (WebDAV DELETE). Confirmé côté carte."""
    c = _ctx(qui)
    if not c:
        return _vide("aucun acces")
    hote, compte, auth = c
    segs = _segments(chemin)
    if segs is None or not segs:
        return _vide("chemin refuse")
    url = _url_dav(hote, compte, segs)
    try:
        async with httpx.AsyncClient(verify=False, timeout=15, auth=auth) as cli:
            r = await cli.delete(url)
    except Exception as e:
        return _vide("action impossible : %s" % type(e).__name__)
    if r.status_code in (200, 204):
        return {"ok": True}
    if r.status_code == 404:
        return _vide("deja absent")
    return _vide("suppression refusee (%d)" % r.status_code)


async def televerser(qui: str, chemin: str, nom: str, data: bytes) -> dict:
    """Téléverse un fichier dans un dossier (WebDAV PUT). `chemin` = dossier."""
    c = _ctx(qui)
    if not c:
        return _vide("aucun acces")
    hote, compte, auth = c
    segs = _segments(chemin)
    nseg = _segments(nom)
    if segs is None or nseg is None or len(nseg) != 1:
        return _vide("chemin ou nom refuse")
    url = _url_dav(hote, compte, segs + nseg)
    try:
        async with httpx.AsyncClient(verify=False, timeout=60, auth=auth) as cli:
            r = await cli.put(url, content=data)
    except Exception as e:
        return _vide("envoi impossible : %s" % type(e).__name__)
    if r.status_code in (200, 201, 204):
        return {"ok": True, "nom": nom}
    if r.status_code == 507:
        return _vide("quota insuffisant")
    return _vide("envoi refuse (%d)" % r.status_code)
