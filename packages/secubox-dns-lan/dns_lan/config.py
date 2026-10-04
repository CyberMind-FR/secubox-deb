# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Lecture et validation de /etc/secubox/dns-lan.toml : rien d'inconnu ne sort d'ici vers un fichier de configuration."""
import ipaddress
import re
from pathlib import Path

DOSSIER_UNBOUND = "/etc/unbound/unbound.conf.d"
_NOM = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)*[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
CHEMIN_RESEAU = re.compile(r"^/[A-Za-z0-9_./-]+\.conf$")


class ErreurConfig(ValueError):
    """Une valeur du TOML est invalide : rien n'est écrit."""


def _sec(brut: dict, nom: str, attendu: dict) -> dict | None:
    s = brut.get(nom)
    if s is None:
        return None
    if not isinstance(s, dict):
        raise ErreurConfig(f"[{nom}] doit être une table")
    inconnu = set(s) - set(attendu)
    if inconnu:
        raise ErreurConfig(f"[{nom}] : clé inconnue {sorted(inconnu)}")
    manquant = [k for k, requis in attendu.items() if requis and k not in s]
    if manquant:
        raise ErreurConfig(f"[{nom}] : clé manquante {manquant}")
    return s


def adresse(v, quoi: str) -> str:
    if not isinstance(v, str):
        raise ErreurConfig(f"{quoi} : adresse attendue")
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        raise ErreurConfig(f"{quoi} : adresse IP invalide") from None


def reseau(v, quoi: str) -> str:
    if not isinstance(v, str):
        raise ErreurConfig(f"{quoi} : réseau attendu")
    try:
        return str(ipaddress.ip_network(v, strict=False))
    except ValueError:
        raise ErreurConfig(f"{quoi} : réseau CIDR invalide") from None


def nom_dns(v, quoi: str) -> str:
    if not isinstance(v, str):
        raise ErreurConfig(f"{quoi} : nom attendu")
    n = v.strip().rstrip(".").lower()
    if not _NOM.match(n):
        raise ErreurConfig(f"{quoi} : nom de domaine invalide")
    return n


def _liste_reseaux(v, quoi: str, vide_ok: bool = False) -> list[str]:
    if not isinstance(v, list) or (not v and not vide_ok):
        raise ErreurConfig(f"{quoi} : liste non vide attendue")
    return [reseau(x, quoi) for x in v]


def _chemin_absolu(v, quoi: str) -> str:
    if not isinstance(v, str) or not v.startswith("/") or "\n" in v or ".." in Path(v).parts:
        raise ErreurConfig(f"{quoi} : chemin absolu attendu")
    return v


def valider(brut: dict) -> dict:
    """TOML brut → configuration normalisée ; ErreurConfig au premier défaut."""
    if not isinstance(brut, dict):
        raise ErreurConfig("fichier illisible")
    inconnu = set(brut) - {"unbound", "lan", "ipv6", "vue_locale", "hote"}
    if inconnu:
        raise ErreurConfig(f"section inconnue {sorted(inconnu)}")
    cfg: dict = {"dossier": DOSSIER_UNBOUND}
    s = _sec(brut, "unbound", {"dossier": True})
    if s:
        cfg["dossier"] = _chemin_absolu(s["dossier"], "[unbound] dossier")
    s = _sec(brut, "lan", {"interface": True, "acces": True})
    if s:
        cfg["lan"] = {"interface": adresse(s["interface"], "[lan] interface"), "acces": _liste_reseaux(s["acces"], "[lan] acces")}
    s = _sec(brut, "ipv6", {"stable": True, "interfaces": True, "acces": True, "dropin_reseau": True})
    if s:
        stable = s["stable"]
        if not isinstance(stable, str) or "/" not in stable:
            raise ErreurConfig("[ipv6] stable : adresse avec préfixe attendue (ex. 2001:db8::200/64)")
        a, _, p = stable.partition("/")
        if not p.isdigit() or not 0 < int(p) <= 128:
            raise ErreurConfig("[ipv6] stable : préfixe invalide")
        ifs = s["interfaces"]
        if not isinstance(ifs, list):
            raise ErreurConfig("[ipv6] interfaces : liste attendue")
        chemin = _chemin_absolu(s["dropin_reseau"], "[ipv6] dropin_reseau")
        if not CHEMIN_RESEAU.match(chemin):
            raise ErreurConfig("[ipv6] dropin_reseau : un fichier .conf attendu")
        cfg["ipv6"] = {"stable": f"{adresse(a, '[ipv6] stable')}/{int(p)}", "interfaces": [adresse(x, "[ipv6] interfaces") for x in ifs],
                       "acces": _liste_reseaux(s["acces"], "[ipv6] acces"), "dropin_reseau": chemin}
    s = _sec(brut, "vue_locale", {"zone": True, "adresse": True})
    if s:
        cfg["vue_locale"] = {"zone": nom_dns(s["zone"], "[vue_locale] zone"), "adresse": adresse(s["adresse"], "[vue_locale] adresse")}
    hotes = brut.get("hote")
    if hotes is not None:
        if not isinstance(hotes, list):
            raise ErreurConfig("[[hote]] doit être une liste de tables")
        vus, sortie = set(), []
        for h in hotes:
            if not isinstance(h, dict) or set(h) - {"nom", "adresse", "ttl"} or "nom" not in h or "adresse" not in h:
                raise ErreurConfig("[[hote]] : nom et adresse requis, ttl facultatif")
            ttl = h.get("ttl", 300)
            if not isinstance(ttl, int) or isinstance(ttl, bool) or not 1 <= ttl <= 86400:
                raise ErreurConfig("[[hote]] ttl : entier entre 1 et 86400")
            n = nom_dns(h["nom"], "[[hote]] nom")
            if n in vus:
                raise ErreurConfig(f"[[hote]] {n} : doublon")
            vus.add(n)
            sortie.append({"nom": n, "adresse": adresse(h["adresse"], "[[hote]] adresse"), "ttl": ttl})
        if sortie:
            cfg["hote"] = sortie
    return cfg
