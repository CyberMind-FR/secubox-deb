# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Indicateurs d'adresses reçus des pairs du maillage (#3723, tâche 4) : `secubox-waf-indices` (oneshot, minuterie de
5 min, compte `secubox`).

Chaque box publie ses indicateurs (`wafctl indice-partager`, geste `partager` de gk2) ; secubox-mirrornet livre ceux
des pairs sous `livraisons/ip-indices/<did-hex32>.json` (objet vérifié, fournisseur au niveau de confiance requis).
Ce service ne bannit JAMAIS à l'aveugle :

- une adresse reçue est notée avec l'instant de sa RÉCEPTION ici (premier passage qui la voit) ;
- elle n'est bannie (24 h, `sudo -n wafctl ban <ip> 86400s --exiger-protegees`, motif `indice-maillage:<famille>`)
  que si le journal des menaces LOCAL la montre hostile APRÈS cette réception : catégorie hors des familles neutres,
  ni `leurre_redirige` (le leurre de la box), ni `rotation`, ni gravité `audit` ;
- gardes : forme (adresse publique canonique), porte et liste blanche du mode SADE (si publié sur cette box), pairs du
  maillage (wg_mesh.json, threatmesh /peers si la socket existe), robots vérifiés (FCrDNS), puis les gardes root de
  `wafctl` / `waf-blocs` (privé, box, plages protégées exigées, pairs WireGuard) ; une source de pairs illisible :
  l'adresse attend la passe suivante, jamais un ban dans le doute ;
- 30 bans par heure glissante au plus ; un indicateur échu est oublié ;
- déjà dans `waf_ban` / `waf_ban6` de cette box (le WAF local l'a bannie lui-même) : rien n'est posé, l'adresse est
  seulement revue (audit `waf-indice-deja-bannie`) — un retour arrière ne retire ainsi jamais le ban du WAF local ;
  ensemble illisible : l'adresse attend ;
- audit `waf-indice-demande` AVANT le ban, `waf-indice` après (un ban non audité est retiré) ; l'adresse bannie ou
  revue entre dans les `revus` de la publication de CETTE box (`wafctl indice-revu`), mesure « reproduit sur le
  maillage ».

Lectures bornées : 64 livraisons, 2 Mio et 500 indicateurs chacune, 16 Mio de la fin du journal des menaces.

Mesure (`indices_etat`, tâche 11) : chaque passe écrit le résumé `/run/secubox/waf-indices-etat.json` (0644) —
`partages` (indicateurs non échus de la publication locale), `revus_chez_pairs` (adresses partagées ici qu'au moins un
pair a revues), `contenus_chez_pairs` (couples pair × adresse partagée ici et revue chez ce pair). SADE (secubox-soc) le
lit sans importer ce module ; il n'est cru que s'il appartient à root ou à `secubox`, sans écriture du groupe ni des
autres, et daté de moins de 30 min.
"""
from __future__ import annotations

import json
import logging
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from api import gestes_ia as _g
except ImportError:  # pragma: no cover — lancé depuis /usr/lib/secubox/waf/api
    import gestes_ia as _g  # type: ignore[no-redef]

log = logging.getLogger("secubox.waf.indices")

LIVRAISONS = Path("/var/lib/secubox-mirrornet-partage/livraisons/ip-indices")
PUBLICATION = Path("/var/lib/secubox/waf/ip-indices-publication.json")
ETAT = Path("/var/lib/secubox-waf-indices/etat.json")
RESUME = Path("/run/secubox/waf-indices-etat.json")
AUDIT_LOG = Path("/var/log/secubox/audit.log")
MENACES = Path(os.environ.get("SECUBOX_WAF_THREATS_LOG") or "/var/log/secubox/waf/waf-threats.log")

WAFCTL = "/usr/sbin/wafctl"
_SUDO = ["sudo", "-n"]
_DELAI_S = 30
DUREE_BAN_S = 86_400
PLAFOND_HEURE = 30
HEURE = 3600
LIVRAISONS_MAX = 64
INDICATEURS_MAX = 500
REVUS_MAX = 500
TAILLE_LIVRAISON_MAX = 2 * 1024 * 1024
TAILLE_INDEX_MAX = 256 * 1024
TAILLE_MENACES = 16 * 1024 * 1024
TAILLE_ETAT_MAX = 8 * 1024 * 1024
TAILLE_RESUME_MAX = 64 * 1024
RECUS_MAX = LIVRAISONS_MAX * INDICATEURS_MAX
#: Adresses retenues au plus par producteur (un pair ne remplit jamais seul l'état).
QUOTA_PRODUCTEUR = 500
#: Échéance d'un indicateur reçu bornée à la réception : 7 j au plus (durée maximale d'un partage sur gk2).
EXPIRE_MAX_S = 7 * 86_400
RESUME_PERIME_S = 1800
_RESUME_AVANCE_MAX_S = 60
COMPTE_RESUME = "secubox"

#: Familles neutres (mêmes que le corrélateur de secubox-ai, `veille/regles.NEUTRES`), plus la redirection vers le
#: leurre de la box (`leurre_redirige`, gravité `audit`) : rien de cela ne fait d'une adresse une adresse hostile.
#: `rotation` (#3919) : verdict du détecteur de rotation, un constat d'ABSENCE de preuve ; il ne part jamais chez les pairs.
FAMILLES_NEUTRES = frozenset({"ban", "ban_actif", "decision", "inconnue", "body-inspect-skipped", "robots", "garde",
                              "dns", "leurre_redirige", "rotation"})
GRAVITES_NEUTRES = frozenset({"audit"})

_DID = re.compile(r"^did:plc:([0-9a-f]{32})$")
_FAMILLE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_CLIENT_IP = re.compile(rb'"(?:client_ip|ip)"\s*:\s*"([0-9A-Fa-f.:]{2,45})"')


# ── Lectures bornées ───────────────────────────────────────────────────
def _maintenant() -> float:
    return time.time()


def _lire_borne(chemin: Path, maxi: int) -> Optional[bytes]:
    """Octets d'un fichier ORDINAIRE (jamais un lien, un tube, un dossier), sans écriture des autres, d'au plus `maxi`
    octets ; None sinon."""
    fd = -1
    try:
        fd = os.open(str(chemin), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o002 or st.st_size > maxi:
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            brut = f.read(maxi + 1)
        return brut if len(brut) <= maxi else None
    except OSError:
        return None
    finally:
        if fd >= 0:
            os.close(fd)


def _lire_json(chemin: Path, maxi: int) -> Any:
    brut = _lire_borne(chemin, maxi)
    if brut is None:
        return None
    try:
        return json.loads(brut.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def _ecrire_atomique(chemin: Path, doc: Any, mode: int) -> None:
    """Temporaire exclusif du même dossier, `mode` explicite, fsync, renommage ; jamais à travers un lien."""
    fd, tmp = tempfile.mkstemp(dir=str(chemin.parent), prefix=f".{chemin.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), mode)
            json.dump(doc, f, ensure_ascii=True, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _adresse(v: Any) -> Optional[Any]:
    """Adresse publique canonique (règles de `gestes_ia.forme_limite`), None sinon."""
    try:
        return _g.forme_limite(v)
    except ValueError:
        return None


def _contenu(c: Any) -> Optional[Tuple[List[dict], List[str]]]:
    """(indicateurs, revus) d'une livraison au schéma EXACT de MirrorNet ; None si le contenu est hors schéma (le
    producteur entier est alors ignoré)."""
    if not isinstance(c, dict) or set(c) != {"format", "jeu", "indicateurs", "revus"}:
        return None
    if type(c["format"]) is not int or c["format"] != 1 or c["jeu"] != "ip-indices":
        return None
    ind, rev = c["indicateurs"], c["revus"]
    if not isinstance(ind, list) or not isinstance(rev, list) or len(ind) > INDICATEURS_MAX or len(rev) > REVUS_MAX:
        return None
    indicateurs = []
    for i in ind:
        if (not isinstance(i, dict) or set(i) != {"ip", "famille", "expire"} or _adresse(i["ip"]) is None
                or not isinstance(i["famille"], str) or not _FAMILLE.match(i["famille"])
                or type(i["expire"]) is not int):
            return None
        indicateurs.append({"ip": i["ip"], "famille": i["famille"], "expire": i["expire"]})
    if not all(isinstance(r, str) and _adresse(r) is not None for r in rev):
        return None
    return indicateurs, list(rev)


def lire_livraisons() -> Optional[Dict[str, Tuple[List[dict], List[str]]]]:
    """{did : (indicateurs, revus)} des producteurs de `index.json` (64 au plus, did conforme, fichier ordinaire borné,
    contenu au schéma) ; un producteur défectueux n'affecte pas les autres. Index absent ou illisible : None (on ne
    sait pas ce que les pairs livrent : ni réception, ni oubli, ni compte des pairs)."""
    idx = _lire_json(LIVRAISONS / "index.json", TAILLE_INDEX_MAX)
    if not isinstance(idx, dict):
        log.warning("indices : index des livraisons absent ou illisible, livraisons inconnues à cette passe")
        return None
    res: Dict[str, Tuple[List[dict], List[str]]] = {}
    for did in list(idx)[:LIVRAISONS_MAX]:
        m = _DID.match(did) if isinstance(did, str) else None
        if not m:
            continue
        v = _contenu(_lire_json(LIVRAISONS / (m.group(1) + ".json"), TAILLE_LIVRAISON_MAX))
        if v is None:
            log.warning("indices : livraison de %s illisible ou hors schéma, ignorée", m.group(1)[:12])
            continue
        res[did] = v
    return res


def vues_hostiles(ips: Set[str]) -> Dict[str, float]:
    """{ip : dernier instant hostile} pour les adresses de `ips` dans la FIN du journal des menaces local (16 Mio au
    plus). Hostile : famille de la catégorie hors `FAMILLES_NEUTRES`, gravité hors `GRAVITES_NEUTRES`, `timestamp`
    RFC 3339 avec décalage. Journal absent : {} ; illisible : lève `_g.Illisible` (aucun ban sur une lecture ratée)."""
    if not ips:
        return {}
    try:
        lignes = _g._lire_fin_octets(MENACES, TAILLE_MENACES)
    except OSError as e:
        raise _g.Illisible(f"journal des menaces : {type(e).__name__}") from None
    vues: Dict[str, float] = {}
    for ligne in lignes or []:
        m = _CLIENT_IP.search(ligne)
        if not m:
            continue
        brut = m.group(1).decode("ascii")
        if brut not in ips and brut.lower() not in ips:
            continue
        try:
            e = json.loads(ligne)
        except ValueError:
            continue
        if not isinstance(e, dict):
            continue
        ip = e.get("client_ip") if isinstance(e.get("client_ip"), str) else e.get("ip")
        if ip not in ips:
            continue
        fam = _g.famille(e.get("category"))
        if not fam or fam in FAMILLES_NEUTRES or e.get("severity") in GRAVITES_NEUTRES:
            continue
        instant = _g._instant(e.get("timestamp")) if isinstance(e.get("timestamp"), str) else None
        if instant is not None and instant > vues.get(ip, float("-inf")):
            vues[ip] = instant
    return vues


# ── État ───────────────────────────────────────────────────────────────
def _etat_vierge() -> Dict[str, Any]:
    return {"format": 1, "recus": {}, "appliques": {}, "bans": []}


def lire_etat() -> Dict[str, Any]:
    """État du service (dossier 0700 de l'unité) ; illisible ou absent : état vierge (les réceptions recommencent, rien
    n'est banni pour autant : il faut une vue hostile postérieure à la nouvelle réception)."""
    d = _lire_json(ETAT, TAILLE_ETAT_MAX)
    if not (isinstance(d, dict) and d.get("format") == 1 and isinstance(d.get("recus"), dict)
            and isinstance(d.get("appliques"), dict) and isinstance(d.get("bans"), list)):
        return _etat_vierge()
    recus = {ip: r for ip, r in d["recus"].items() if isinstance(r, dict) and _g._entier(r.get("recu"))
             and _g._entier(r.get("expire")) and isinstance(r.get("famille"), str) and _FAMILLE.match(r["famille"])
             and isinstance(r.get("source"), str) and _DID.match(r["source"]) and _adresse(ip) is not None}
    appliques = {ip: a for ip, a in d["appliques"].items() if isinstance(a, dict) and _g._entier(a.get("at"))}
    bans = [t for t in d["bans"] if _g._entier(t)]
    return {"format": 1, "recus": recus, "appliques": appliques, "bans": bans}


# ── Gestes ─────────────────────────────────────────────────────────────
def _executer(argv: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, check=False, timeout=_DELAI_S, capture_output=True, text=True)


def _lancer(argv: List[str]) -> Optional[subprocess.CompletedProcess]:
    try:
        return _executer(argv)
    except (subprocess.TimeoutExpired, OSError) as e:
        log.error("indices : %s injoignable : %s", argv[3] if len(argv) > 3 else argv, type(e).__name__)
        return None


def _auditer(action: str, detail: str) -> None:
    """Une ligne d'`audit.log` (ajout seul) ; lève OSError si elle n'a pas pu être écrite."""
    ligne = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": "waf", "action": action,
                        "detail": detail[:300], "by": "secubox-waf-indices"}, ensure_ascii=False) + "\n"
    fd = os.open(str(AUDIT_LOG), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        os.write(fd, ligne.encode("utf-8"))
    finally:
        os.close(fd)


def _auditer_sans_lever(action: str, detail: str) -> None:
    try:
        _auditer(action, detail)
    except OSError as e:
        log.warning("indices : audit %s non écrit : %s", action, type(e).__name__)


def _protegee(ip: str) -> bool:
    """Pair du maillage (wg_mesh.json ; threatmesh /peers si sa socket existe : une box sans threatmesh n'en a pas)
    ou robot vérifié. Lève `_g.ProtectionInconnue` si une source présente ne répond pas."""
    cible = _g.forme_limite(ip)
    pairs = _g.pairs_wg_mesh()
    if os.path.exists(_g.SOCKET_THREATMESH):
        pairs += _g.pairs_threatmesh()
    if any(_g._touche(cible, n) for n in pairs):
        return True
    return bool(_g.robot_verifie(ip))


def deja_bannie_ici(ip: str) -> bool:
    """L'adresse est-elle déjà dans `waf_ban` / `waf_ban6` de CETTE box (lecture stricte, argv exact du sudoers
    SBX_WAF_NFTLIST) ? Lève `_g.Illisible` : sans le savoir, rien n'est posé (un retour arrière retirerait le ban du
    WAF local)."""
    v6 = ":" in ip
    nom = "waf_ban6" if v6 else "waf_ban"
    r = _lancer(_SUDO + (_g.NFT_LISTE_WAF_BAN6 if v6 else _g.NFT_LISTE_WAF_BAN))
    if r is None or r.returncode != 0 or not r.stdout:
        raise _g.Illisible("nft : ensemble illisible")
    try:
        doc = json.loads(r.stdout)
        jeux = [b["set"] for b in doc["nftables"] if isinstance(b, dict) and "set" in b]
    except (ValueError, KeyError, TypeError):
        raise _g.Illisible("nft : réponse illisible") from None
    if len(jeux) != 1 or not isinstance(jeux[0], dict) or jeux[0].get("name") != nom:
        raise _g.Illisible(f"nft : ensemble {nom} absent")
    for elem in jeux[0].get("elem", []) or []:
        e = elem.get("elem") if isinstance(elem, dict) else None
        val = e.get("val") if isinstance(e, dict) else elem
        if isinstance(val, str) and _adresse(val) is not None and str(_g.forme_limite(val)) == ip:
            return True
    return False


def _revoir(ip: str) -> None:
    rv = _lancer(_SUDO + [WAFCTL, "indice-revu", ip])
    if rv is None or rv.returncode != 0:
        log.warning("indices : %s non notée dans les revus", ip)


def _motif_refus(r: subprocess.CompletedProcess) -> str:
    m = _g._motif_sortie(r)
    return m if m else "wafctl"


def appliquer(ip: str, famille: str, sade: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """(issue, motif) : `banni`, `revu` (déjà bannie par le WAF local : rien n'est posé, l'adresse est seulement
    revue), `refus` (définitif pour cet indicateur) ou `attente` (nouvel essai à la passe suivante). Toutes les gardes
    passent AVANT l'audit de la demande, puis le ban, puis la revue."""
    motif = _g.porte_sade("ban", sade)
    if motif:
        return "attente", motif
    cible = _g.forme_limite(ip)
    try:
        if _g.protegee_par_sade(cible, sade):
            return "refus", "protegee"
    except _g.Illisible:
        return "attente", "etat"
    try:
        if _protegee(ip):
            return "refus", "protegee"
    except _g.ProtectionInconnue as e:
        log.warning("indices : cibles protégées inconnues : %s", e)
        return "attente", "protegee_inconnue"
    resume = f"cible {ip} {DUREE_BAN_S}s motif indice-maillage:{famille}"
    try:
        deja = deja_bannie_ici(ip)
    except _g.Illisible as e:
        log.warning("indices : %s", e)
        return "attente", "etat"
    if deja:
        # Le WAF local l'a déjà bannie (elle y est hostile) : rien n'est posé, donc rien ne sera jamais retiré ici.
        _auditer_sans_lever("waf-indice-deja-bannie", f"cible {ip} motif indice-maillage:{famille}")
        _revoir(ip)
        return "revu", ""
    try:
        _auditer("waf-indice-demande", resume)
    except OSError:
        return "attente", "audit"
    r = _lancer(_SUDO + [WAFCTL, "ban", ip, f"{DUREE_BAN_S}s", "--exiger-protegees"])
    if r is None:
        # peut-être posé : retiré, jamais un ban allongé depuis par un autre (fin au plus, revue finale I4)
        _lancer(_SUDO + [WAFCTL, "unban", ip, str(int(_maintenant()) + DUREE_BAN_S)])
        return "attente", "wafctl"
    if r.returncode != 0:
        motif = _motif_refus(r)
        _auditer_sans_lever("waf-indice-refus", f"{resume} refus {motif}")
        return ("attente" if motif in ("etat", "audit", "wafctl", "garde_illisible") else "refus"), motif
    try:
        _auditer("waf-indice", resume)
    except OSError:
        defait = _lancer(_SUDO + [WAFCTL, "unban", ip, str(int(_maintenant()) + DUREE_BAN_S)])
        log.error("indices : ban de %s non audité, %s", ip, "retiré" if defait and defait.returncode == 0
                  else "RETRAIT IMPOSSIBLE")
        return "attente", "audit"
    _revoir(ip)
    return "banni", ""


# ── Passe ──────────────────────────────────────────────────────────────
def passe(maintenant: Optional[float] = None) -> Dict[str, Any]:
    """Une passe : réception, vue locale, bans, état, résumé. Rend `{"recus", "bannis", "revus", "refus",
    "attente"}`."""
    now = int(maintenant if maintenant is not None else _maintenant())
    etat = lire_etat()
    livraisons = lire_livraisons()
    if livraisons is not None:
        # Oubli : une adresse qu'aucune livraison actuelle ne porte plus (indicateur retiré, pair résilié ou descendu
        # sous le seuil de confiance) n'est plus retenue.
        livrees = {i["ip"] for indicateurs, _ in livraisons.values() for i in indicateurs}
        for ip in [ip for ip in etat["recus"] if ip not in livrees]:
            del etat["recus"][ip]
        # Réception : la première vue d'une adresse fait foi (instant, famille, producteur) ; échéance bornée à 7 j ;
        # 500 adresses retenues au plus par producteur ; un indicateur échu n'est pas retenu.
        par_source: Dict[str, int] = {}
        for r in etat["recus"].values():
            par_source[r["source"]] = par_source.get(r["source"], 0) + 1
        for did, (indicateurs, _) in livraisons.items():
            for i in indicateurs:
                if i["expire"] <= now or i["ip"] in etat["recus"] or len(etat["recus"]) >= RECUS_MAX:
                    continue
                if par_source.get(did, 0) >= QUOTA_PRODUCTEUR:
                    break
                etat["recus"][i["ip"]] = {"recu": now, "famille": i["famille"], "source": did,
                                          "expire": min(i["expire"], now + EXPIRE_MAX_S)}
                par_source[did] = par_source.get(did, 0) + 1
    for ip in [ip for ip, r in etat["recus"].items() if r["expire"] <= now]:
        del etat["recus"][ip]
    etat["appliques"] = {ip: a for ip, a in etat["appliques"].items() if ip in etat["recus"]}
    etat["bans"] = [t for t in etat["bans"] if now - HEURE < t <= now + _RESUME_AVANCE_MAX_S]
    bilan = {"recus": len(etat["recus"]), "bannis": 0, "revus": 0, "refus": 0, "attente": 0}

    en_attente = {ip for ip in etat["recus"] if ip not in etat["appliques"]}
    try:
        vues = vues_hostiles(en_attente)
    except _g.Illisible as e:
        log.warning("indices : %s ; aucun ban à cette passe", e)
        vues = {}
    candidats = sorted((ip for ip in en_attente if vues.get(ip, float("-inf")) > etat["recus"][ip]["recu"]),
                       key=lambda ip: vues[ip])
    sade = _g.lire_sade() if candidats else None
    for ip in candidats:
        if len(etat["bans"]) >= PLAFOND_HEURE:
            log.warning("indices : plafond de %s bans par heure atteint, la suite attend", PLAFOND_HEURE)
            bilan["attente"] += len(candidats) - sum(bilan[k] for k in ("bannis", "revus", "refus", "attente"))
            break
        issue, motif = appliquer(ip, etat["recus"][ip]["famille"], sade)
        if issue == "banni":
            etat["appliques"][ip] = {"at": now, "issue": "banni"}
            etat["bans"].append(now)
            bilan["bannis"] += 1
        elif issue == "revu":
            etat["appliques"][ip] = {"at": now, "issue": "revu"}
            bilan["revus"] += 1
        elif issue == "refus":
            etat["appliques"][ip] = {"at": now, "issue": "refus", "motif": motif}
            bilan["refus"] += 1
        else:
            bilan["attente"] += 1
    try:
        _ecrire_atomique(ETAT, etat, 0o600)
    except OSError as e:
        log.error("indices : état non écrit : %s", type(e).__name__)
    try:
        _ecrire_atomique(RESUME, {"format": 1, "maj": now, **etat_depuis(livraisons, now),
                                  "recus": len(etat["recus"])}, 0o644)
    except OSError as e:
        log.warning("indices : résumé non écrit : %s", type(e).__name__)
    return bilan


def etat_depuis(livraisons: Optional[Dict[str, Tuple[List[dict], List[str]]]], now: int) -> Dict[str, Optional[int]]:
    """Mesure de la tâche 11 depuis la publication LOCALE et les livraisons reçues. Jamais un zéro inventé : publication
    absente ou illisible ⇒ les trois valeurs None ; livraisons inconnues (index illisible) ⇒ comptes des pairs None."""
    pub = _lire_json(PUBLICATION, TAILLE_LIVRAISON_MAX)
    if not (isinstance(pub, dict) and pub.get("jeu") == "ip-indices" and isinstance(pub.get("indicateurs"), list)):
        return {"partages": None, "revus_chez_pairs": None, "contenus_chez_pairs": None}
    partages = {i["ip"] for i in pub["indicateurs"][:INDICATEURS_MAX] if isinstance(i, dict)
                and isinstance(i.get("ip"), str) and _g._entier(i.get("expire")) and i["expire"] > now}
    if livraisons is None:
        return {"partages": len(partages), "revus_chez_pairs": None, "contenus_chez_pairs": None}
    revus = [partages & set(rev) for _, rev in livraisons.values()]
    return {"partages": len(partages), "revus_chez_pairs": len(set().union(*revus)) if revus else 0,
            "contenus_chez_pairs": sum(len(r) for r in revus)}


def _uids_resume() -> Set[int]:
    try:
        return {0, pwd.getpwnam(COMPTE_RESUME).pw_uid}
    except KeyError:
        return {0}


def indices_etat() -> Optional[Dict[str, Optional[int]]]:
    """`{"partages", "revus_chez_pairs", "contenus_chez_pairs"}` du dernier résumé, ou None (relevé indisponible :
    absent, illisible, d'un autre compte que root ou secubox, modifiable par le groupe ou les autres, périmé, ou
    publication locale illisible). Livraisons inconnues : les deux comptes des pairs valent None."""
    fd = -1
    try:
        fd = os.open(str(RESUME), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid not in _uids_resume() or st.st_mode & 0o022
                or st.st_size > TAILLE_RESUME_MAX):
            return None
        with os.fdopen(fd, "rb") as f:
            fd = -1
            d = json.loads(f.read(TAILLE_RESUME_MAX))
    except (OSError, ValueError, UnicodeDecodeError, RecursionError):
        return None
    finally:
        if fd >= 0:
            os.close(fd)
    cles = ("partages", "revus_chez_pairs", "contenus_chez_pairs")
    if not isinstance(d, dict) or not _g._entier(d.get("maj")) or not _g._entier(d.get("partages")):
        return None
    if not all(d.get(k) is None or _g._entier(d.get(k)) for k in cles[1:]):
        return None
    if (d.get("revus_chez_pairs") is None) != (d.get("contenus_chez_pairs") is None):
        return None
    age = _maintenant() - d["maj"]
    if age > RESUME_PERIME_S or age < -_RESUME_AVANCE_MAX_S:
        return None
    return {k: d[k] for k in cles}


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    bilan = passe()
    if bilan["bannis"] or bilan["revus"] or bilan["refus"]:
        log.info("indices : %s", bilan)
    return 0
