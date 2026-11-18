# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Normalisation d'une ligne de gk2 en événement de veille.db (V2 § 6, § 7 ; phase 0 § 5), #3720.

Les champs venant de gk2 sont des DONNÉES NON FIABLES : tronqués, jamais interprétés. Familles et gravités telles que
gk2 les nomme (`famille` = avant « : » de `category`/`cat`, `sous_famille` = après, suffixe `|prolonge` → attribut).
Horodatages convertis en UTC RFC 3339. `client_ip = local` marqué (`local`), plages de documentation gardées mais
marquées `exclu_correlation`, autotest du WAF (`SecuBox-WAF-SelfTest/1`) marqué `autotest`.
"""
import hashlib
import ipaddress
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

MESSAGE_MAX = 512
CHAMP_MAX = 256
ATTRIBUTS_MAX = 8192
AUTOTEST = "SecuBox-WAF-SelfTest/1"
DOCUMENTATION = tuple(ipaddress.ip_network(p) for p in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
                                                       "2001:db8::/32"))
# Champs connus rangés dans des colonnes ; tout le reste part (tronqué) dans attributs_json.
_CONNUS = {"category", "cat", "famille", "menace", "severity", "sev", "gravite", "timestamp", "ts", "at",
           "created_at", "debut", "genere_le", "client_ip", "ip", "target", "cible", "host", "vhost", "country",
           "pays", "service", "rule_id", "message", "raison", "reason", "motif"}


@dataclass
class Evenement:
    id: str
    source: str
    id_source: Optional[str]
    noeud: str
    horodatage: str
    famille: str
    sous_famille: Optional[str]
    gravite: str
    ip_src: Optional[str]
    bloc24: Optional[str]
    pays: Optional[str]
    service: Optional[str]
    vhost: Optional[str]
    message: Optional[str]
    attributs: dict = field(default_factory=dict)
    empreinte: str = ""
    cree_le: str = ""

    def ligne(self):
        """Valeurs dans l'ordre des colonnes de la table `evenements`."""
        attributs = json.dumps(self.attributs, ensure_ascii=False, sort_keys=True)
        if len(attributs) > ATTRIBUTS_MAX:
            attributs = json.dumps({"tronque": True}, sort_keys=True)
        return (self.id, self.source, self.id_source, self.noeud, self.horodatage, self.famille, self.sous_famille,
                self.gravite, self.ip_src, self.bloc24, self.pays, self.service, self.vhost, self.message,
                attributs, self.empreinte, self.cree_le)


COLONNES = ("id", "source", "id_source", "noeud", "horodatage", "famille", "sous_famille", "gravite", "ip_src",
            "bloc24", "pays", "service", "vhost", "message", "attributs_json", "empreinte", "cree_le")


def rfc3339(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def texte(v: Any, n: int = CHAMP_MAX) -> Optional[str]:
    """Chaîne tronquée sans caractère de contrôle ; None pour vide/absent."""
    if v is None or isinstance(v, (dict, list)):
        return None
    s = "".join(c if c.isprintable() else " " for c in str(v))[:n].strip()
    return s or None


def utc(v: Any, naif_utc: bool = False) -> Optional[str]:
    """Époque (s) ou ISO 8601 avec décalage → UTC RFC 3339 ; None si illisible. Un ISO SANS décalage est ambigu
    (heure locale de gk2 ?) : None (ligne ignorée et comptée), sauf `naif_utc` pour une source documentée en UTC."""
    if isinstance(v, bool) or v is None:
        return None
    try:
        if isinstance(v, (int, float)) or (isinstance(v, str) and v.replace(".", "", 1).isdigit()):
            return rfc3339(datetime.fromtimestamp(float(v), timezone.utc))
        d = datetime.fromisoformat(str(v)[:40].replace("Z", "+00:00"))
    except (ValueError, OverflowError, OSError):
        return None
    if d.tzinfo is None:
        if not naif_utc:
            return None
        d = d.replace(tzinfo=timezone.utc)
    return rfc3339(d)


def _premier(brut: dict, *cles):
    for c in cles:
        v = brut.get(c)
        if v not in (None, ""):
            return v
    return None


def famille(categorie: Any) -> tuple[str, Optional[str], bool]:
    """`scanners:x|prolonge` → ('scanners', 'x', True)."""
    c = texte(categorie, 128) or "inconnue"
    prolonge = False
    if c.endswith("|prolonge"):
        c, prolonge = c[: -len("|prolonge")], True
    fam, _, sous = c.partition(":")
    return (fam or "inconnue"), (sous or None), prolonge


def adresse(v: Any) -> tuple[Optional[str], Optional[str], dict]:
    """(ip, bloc24, marques). `local` → marque `local` sans ip ; documentation → `exclu_correlation`."""
    s = texte(v, 64)
    if s is None:
        return None, None, {}
    if s == "local":
        return None, None, {"local": True}
    try:
        ip = ipaddress.ip_address(s.split("/")[0])
    except ValueError:
        return None, None, {"ip_illisible": s}
    marques = {}
    if any(ip in r for r in DOCUMENTATION if r.version == ip.version):
        marques["exclu_correlation"] = "documentation"
    bloc = str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address) + "/24" if ip.version == 4 else None
    return str(ip), bloc, marques


def _valeur(v, profondeur=0):
    """Valeur non fiable rangée dans attributs_json : scalaires gardés, chaînes tronquées, listes et objets bornés."""
    if isinstance(v, (int, float, bool)) or v is None:
        return v
    if profondeur < 2 and isinstance(v, list):
        return [_valeur(x, profondeur + 1) for x in v[:32]]
    if profondeur < 2 and isinstance(v, dict):
        return {texte(a, 64): _valeur(b, profondeur + 1) for a, b in list(v.items())[:32] if texte(a, 64)}
    return texte(v)


def empreinte(source, horodatage, ip, fam, vhost, id_source) -> str:
    """SHA-256 de (source, horodatage, ip, famille, vhost, id_source) — V2 § 6."""
    champs = [x if x is not None else "" for x in (source, horodatage, ip, fam, vhost, id_source)]
    return hashlib.sha256("\x1f".join(champs).encode("utf-8")).hexdigest()


def evenement(source: str, brut: dict, id_source: Any = None, noeud: str = "gk2",
              maintenant: Optional[datetime] = None, famille_defaut: Optional[str] = None,
              naif_utc: bool = False) -> Evenement:
    """Une ligne brute de gk2 → Evenement. Lève ValueError si ce n'est pas un objet ou sans horodatage lisible."""
    if not isinstance(brut, dict):
        raise ValueError("ligne non objet")
    cree = rfc3339(maintenant or datetime.now(timezone.utc))
    h = utc(_premier(brut, "timestamp", "ts", "at", "created_at", "debut", "genere_le"), naif_utc)
    if h is None:
        raise ValueError("horodatage illisible")
    cat = _premier(brut, "category", "cat", "categorie", "famille", "menace") or famille_defaut
    fam, sous, prolonge = famille(cat)
    ip, bloc, marques = adresse(_premier(brut, "client_ip", "ip", "target", "cible"))
    attributs = {}
    for k, v in brut.items():
        cle = texte(k, 64)
        if cle is None or k in _CONNUS:
            continue
        attributs[cle] = _valeur(v)
    attributs.update(marques)
    if prolonge:
        attributs["prolonge"] = True
    if AUTOTEST in str(brut.get("user_agent") or ""):
        attributs["autotest"] = True
        attributs["exclu_correlation"] = "autotest"
    vhost = texte(_premier(brut, "host", "vhost"))
    ids = texte(id_source, 128)
    emp = empreinte(source, h, ip or ("local" if marques.get("local") else None), fam, vhost, ids)
    return Evenement(
        id=str(uuid.UUID(emp[:32])), source=source, id_source=ids, noeud=noeud, horodatage=h, famille=fam,
        sous_famille=sous, gravite=texte(_premier(brut, "severity", "sev", "gravite"), 32) or "info",
        ip_src=ip, bloc24=bloc, pays=texte(_premier(brut, "country", "pays"), 8), service=texte(brut.get("service"), 64),
        vhost=vhost, message=texte(_premier(brut, "message", "rule_id", "raison", "reason", "motif"), MESSAGE_MAX),
        attributs=attributs, empreinte=emp, cree_le=cree)
