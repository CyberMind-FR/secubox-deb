# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""
SecuBox-Deb :: freebox :: contrôle des DNS distribués par la Freebox (#3769)
CyberMind — https://cybermind.fr

TV Privacy, ad-guard et les noms internes ne marchent que si les appareils du réseau interrogent la box. La Freebox annonce
le DNS IPv4 (DHCP) et le DNS IPv6 (DHCPv6/RA, « DNS personnalisés ») : ce module vérifie qu'elle annonce la box, seule, et
selon le réglage alerte ou corrige. Garde-fous :
  - jamais de DNS secondaire (il servirait à contourner le filtrage) ;
  - jamais de correction vers un serveur qui ne répond pas (un DNS mort couperait Internet à tout le réseau) ;
  - chaque écriture sur la Freebox passe par service.regler_dns/regler_dns6 (relue, journalisée).
Réglage : /var/lib/secubox/freebox/dns-reglage.json (écrit par l'API, remplacement atomique). État : dns-controle.json.
"""
import ipaddress
import json
import os
import random
import socket
import struct
import time
import tomllib

DOSSIER = os.environ.get("SECUBOX_FREEBOX_ETAT", "/var/lib/secubox/freebox")
CHEMIN_REGLAGE = os.path.join(DOSSIER, "dns-reglage.json")
CHEMIN_ETAT = os.path.join(DOSSIER, "dns-controle.json")
CHEMIN_DNS_LAN = os.environ.get("SECUBOX_DNS_LAN_TOML", "/etc/secubox/dns-lan.toml")
MODES = ("alerter", "corriger")
DEFAUT = {"actif": True, "mode": "corriger", "ipv4": "auto", "ipv6": "auto"}


def _ecrire_json(chemin, donnees):
    os.makedirs(os.path.dirname(chemin), exist_ok=True)
    tmp = chemin + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(donnees, f, ensure_ascii=False)
    os.replace(tmp, chemin)        # double tampon : jamais de fichier à moitié écrit


def _lire_json(chemin):
    try:
        with open(chemin, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def valider(r):
    """Réglage complet et validé ; ValueError sinon. ipv4/ipv6 : "auto" ou une adresse de la bonne famille."""
    if not isinstance(r, dict):
        raise ValueError("réglage invalide")
    out = dict(DEFAUT)
    for k in r:
        if k not in DEFAUT:
            raise ValueError("clé inconnue : " + str(k))
    if "actif" in r:
        if not isinstance(r["actif"], bool):
            raise ValueError("actif doit être vrai ou faux")
        out["actif"] = r["actif"]
    if "mode" in r:
        if r["mode"] not in MODES:
            raise ValueError("mode : alerter ou corriger")
        out["mode"] = r["mode"]
    for cle, fam in (("ipv4", 4), ("ipv6", 6)):
        if cle in r:
            v = str(r[cle]).strip()
            if v != "auto":
                try:
                    a = ipaddress.ip_address(v)
                except ValueError:
                    raise ValueError(cle + " : adresse invalide") from None
                if a.version != fam or a.is_unspecified or a.is_multicast:
                    raise ValueError(cle + " : adresse invalide")
                v = str(a)
            out[cle] = v
    return out


def lire_reglage(chemin=None):
    d = _lire_json(chemin or CHEMIN_REGLAGE)
    try:
        return valider(d) if d is not None else dict(DEFAUT)
    except ValueError:
        return dict(DEFAUT)


def ecrire_reglage(r, chemin=None):
    r = valider(r)
    _ecrire_json(chemin or CHEMIN_REGLAGE, r)
    return r


def lire_etat(chemin=None):
    return _lire_json(chemin or CHEMIN_ETAT)


def ipv6_stable(chemin=None):
    """IPv6 stable de la box déclarée par secubox-dns-lan (`[ipv6] stable`, sans le préfixe), ou ""."""
    try:
        with open(chemin or CHEMIN_DNS_LAN, "rb") as f:
            v = str(((tomllib.load(f) or {}).get("ipv6") or {}).get("stable") or "")
        return str(ipaddress.ip_interface(v).ip) if v else ""
    except (OSError, tomllib.TOMLDecodeError, ValueError):
        return ""


def ipv6_box(doc_ip, doc_routes):
    """IPv6 de la box à annoncer quand dns-lan.toml n'en déclare pas : sur l'interface de la route par défaut, une adresse fixe
    d'abord, sinon une adresse SLAAC stable (dérivée de la MAC ou « stable-privacy »). Jamais une temporaire ni une dépréciée :
    elles disparaissent en quelques heures et le réseau perdrait son DNS. "" si aucune."""
    from . import maillage as MA
    fixes = MA.ipv6_fixes(doc_ip, doc_routes)
    if fixes:
        return fixes[0]["adresse"]
    wan = MA.interfaces_wan(doc_routes)
    for iface in doc_ip if isinstance(doc_ip, list) else []:
        if str(iface.get("ifname") or "") not in wan:
            continue
        for a in iface.get("addr_info") or []:
            if a.get("family") != "inet6" or a.get("scope") != "global" or a.get("temporary") or a.get("deprecated"):
                continue
            try:
                ad = ipaddress.IPv6Address(a.get("local") or "")
            except ValueError:
                continue
            if ad.is_global:
                return str(ad)
    return ""


def ipv6_auto_relevee(chemin=None):
    """IPv6 de la box relevée par le dernier passage du minuteur (l'API n'a pas accès au netlink)."""
    return str((lire_etat(chemin) or {}).get("ipv6_auto") or "")


def attendus(reglage, ip_box, stable):
    """(ipv4, ipv6) attendus ; "" = pas de valeur connue (cette famille n'est alors pas contrôlée)."""
    v4 = ip_box if reglage["ipv4"] == "auto" else reglage["ipv4"]
    v6 = stable if reglage["ipv6"] == "auto" else reglage["ipv6"]
    return v4 or "", v6 or ""


def repond(serveur, delai=2.0):
    """Le serveur répond-il à une requête DNS (A secubox.in) ? Toute réponse bien formée compte, même NXDOMAIN."""
    ident = random.randint(0, 0xFFFF)
    q = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in ("secubox", "in")) + b"\x00" + struct.pack(">HH", 1, 1)
    fam = socket.AF_INET6 if ":" in serveur else socket.AF_INET
    s = socket.socket(fam, socket.SOCK_DGRAM)
    try:
        s.settimeout(delai)
        s.sendto(q, (serveur, 53))
        r, _ = s.recvfrom(512)
        return len(r) >= 12 and struct.unpack(">H", r[:2])[0] == ident and bool(r[2] & 0x80) and (r[3] & 0x0F) in (0, 3)
    except OSError:
        return False
    finally:
        s.close()


def comparer(dns4, dns6, v4, v6):
    """Écarts entre ce que la Freebox annonce et l'attendu. dns6 = {"use_custom_dns", "dns"}."""
    ecarts = []
    if v4 and dns4 != [v4]:
        ecarts.append({"famille": "ipv4", "annonce": dns4, "attendu": v4,
                       "message": "DNS IPv4 : la Freebox annonce %s au lieu de la box seule." % (", ".join(dns4) or "elle-même")})
    if v6 and (not dns6.get("use_custom_dns") or dns6.get("dns") != [v6]):
        annonce = dns6.get("dns") if dns6.get("use_custom_dns") else []
        ecarts.append({"famille": "ipv6", "annonce": annonce, "attendu": v6,
                       "message": "DNS IPv6 : la Freebox annonce %s au lieu de la box seule." % (", ".join(annonce) or "son propre résolveur")})
    return ecarts


IMPACT = "Les appareils concernés ne passent plus par la box : TV Privacy et le blocage sont contournés."


def resolveurs_tiers(annonce, attendu, ip_freebox, sonde):
    """Serveurs annoncés par la Freebox qui ne sont ni la box, ni la Freebox elle-même, et qui RÉPONDENT : un autre
    résolveur du réseau choisi exprès (autre SecuBox, Pi-hole…). Une box en « auto » ne le remplace jamais (#3769 :
    deux box sur la même Freebox ne se disputent pas son réglage)."""
    return [a for a in annonce if a and a != attendu and a != ip_freebox and sonde(a)]


def controler(svc, ip_box, reglage=None, stable=None, sonde=repond, horloge=time.time, ecrire=None, corriger_force=False):
    """Un passage : lit les deux DNS, compare, corrige si le mode le demande (ou `corriger_force`, geste « Appliquer »).
    Écrit l'état et le rend. Les erreurs Freebox remontent (l'appelant les traduit)."""
    reglage = reglage or lire_reglage()
    stable = (ipv6_stable() or ipv6_auto_relevee()) if stable is None else stable
    v4, v6 = attendus(reglage, ip_box, stable)
    etat = {"verifie_le": int(horloge()), "actif": reglage["actif"], "mode": reglage["mode"], "ipv6_auto": stable,
            "attendu": {"ipv4": v4, "ipv6": v6}, "corrections": [], "refus": [], "delegue": [], "alertes": []}
    dns4 = svc.lire_dns()
    dns6 = svc.lire_dns6()
    etat["annonce"] = {"ipv4": dns4, "ipv6": dns6.get("dns") if dns6.get("use_custom_dns") else [], "ipv6_personnalise": bool(dns6.get("use_custom_dns"))}
    ecarts = comparer(dns4, dns6, v4, v6)
    if ecarts and (corriger_force or (reglage["actif"] and reglage["mode"] == "corriger")):
        ip_fb = getattr(svc, "ip_freebox", lambda: "")()
        for e in ecarts:
            tiers = [] if corriger_force or reglage[e["famille"]] != "auto" else resolveurs_tiers(e["annonce"], e["attendu"], ip_fb, sonde)
            if tiers:
                etat["delegue"].append({"famille": e["famille"], "serveurs": tiers})
                continue
            if not sonde(e["attendu"]):
                etat["refus"].append("%s : %s ne répond pas, la Freebox n'est pas modifiée." % (e["famille"].upper(), e["attendu"]))
                continue
            if e["famille"] == "ipv4":
                svc.regler_dns([v4])
            else:
                svc.regler_dns6(True, [v6])
            etat["corrections"].append(e["famille"])
        dns4, dns6 = svc.lire_dns(), svc.lire_dns6()
        etat["annonce"] = {"ipv4": dns4, "ipv6": dns6.get("dns") if dns6.get("use_custom_dns") else [], "ipv6_personnalise": bool(dns6.get("use_custom_dns"))}
        ecarts = comparer(dns4, dns6, v4, v6)
    delegues = {d["famille"] for d in etat["delegue"]}
    etat["ecarts"] = [e for e in ecarts if e["famille"] not in delegues]
    etat["conforme"] = not etat["ecarts"]
    etat["alertes"] = [e["message"] + " " + IMPACT for e in etat["ecarts"]] + etat["refus"]
    for d in etat["delegue"]:
        etat["alertes"].append("DNS %s : la Freebox annonce %s, un autre résolveur du réseau qui répond (autre SecuBox ?). "
                               "Pas de correction automatique ; « Appliquer maintenant » ou une adresse saisie reprend la main."
                               % (d["famille"].upper(), ", ".join(d["serveurs"])))
    if not v6:                       # un trou du contrôle se voit : jamais de silence sur l'IPv6 (#3769, gk7 du 17/11)
        etat["alertes"].append("DNS IPv6 non contrôlé : aucune IPv6 de la box connue (dns-lan.toml, ou adresse stable de l'interface). "
                               "Saisissez-la dans « DNS IPv6 attendu ».")
    (ecrire or (lambda d: _ecrire_json(CHEMIN_ETAT, d)))(etat)
    return etat


def reinitialiser(svc, ecrire_r=None, ecrire_e=None, horloge=time.time):
    """Rend à la Freebox ses DNS d'origine (IPv4 : elle-même ; IPv6 : personnalisés décochés) et désactive le contrôle."""
    svc.regler_dns([])
    svc.regler_dns6(False, svc.lire_dns6()["dns"])     # décoche seulement : la liste n'est plus annoncée
    r = dict(lire_reglage(), actif=False)
    (ecrire_r or ecrire_reglage)(r)
    etat = {"verifie_le": int(horloge()), "actif": False, "reinitialise": True, "conforme": None, "ecarts": [], "alertes": [],
            "annonce": {"ipv4": svc.lire_dns(), "ipv6": [], "ipv6_personnalise": False}}
    (ecrire_e or (lambda d: _ecrire_json(CHEMIN_ETAT, d)))(etat)
    return etat
