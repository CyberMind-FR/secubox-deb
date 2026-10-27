# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""SecuBox-Deb :: profiles — relevé de validation de CETTE box (#3212).

Quatre niveaux par paquet SecuBox, lus du réel et jamais des métadonnées générées à la construction :
  1. attendu    : fermeture des Depends du méta-paquet de profil installé le plus haut (dpkg de la box) ;
  2. paquet     : version et statut dpkg ;
  3. services   : unités systemd livrées par le paquet (/var/lib/dpkg/info/<paquet>.list) et modules servis par
                  l'agrégateur (/health) — un module monté y est actif même si son unité propre est désactivée ;
  4. ressources : mémoire des unités actives (cgroup entier), CPU par différence avec le relevé précédent.

Sans privilège (utilisateur secubox), toutes les 5 min (secubox-profiles-releve.timer), dans
/var/lib/secubox/profiles/validation/releve.json. annuaire signe le fichier et le
sert aux pairs du maillage (sbx-fleetctl publish-modules). Une sonde en échec rend le relevé PARTIEL, annoncé : jamais
de faux « absent » ni de faux « arrêté »."""
from __future__ import annotations

import contextlib
import http.client
import json
import logging
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

VERSION = 1
DEFAUT = "/var/lib/secubox/profiles/validation/releve.json"     # dossier au compte secubox (postinst)


def chemin_releve() -> Path:
    """Lu à chaque appel (tests, API et CLI s'accordent par SECUBOX_PROFILS_VALIDATION)."""
    return Path(os.environ.get("SECUBOX_PROFILS_VALIDATION", DEFAUT))
SOCKET_AGREGATEUR = "/run/secubox/aggregator.sock"
DPKG_INFO = Path("/var/lib/dpkg/info")

NOM_PAQUET = re.compile(r"(secubox|sbxos)-[a-z0-9][a-z0-9.+-]*")
METAS = ("minimal", "lite", "isp", "full")
PROPRIETES = ("Id", "Type", "ActiveState", "SubState", "UnitFileState", "Result", "ConditionResult", "TriggeredBy",
              "MemoryCurrent", "CPUUsageNSec")
SOMMEIL = ("eager", "on-demand")                     # cycles de vie qui dorment (lifecycle.is_sleepable)

MAX_PAQUETS = 400
MAX_UNITES = 16
MAX_ERREURS = 5
MAX_TEXTE = 200

_UNITE = re.compile(r"/(?:usr/)?lib/systemd/system/([A-Za-z0-9_.:-]+\.(?:service|timer))")
_MODULE = re.compile(r"/usr/lib/secubox/([a-z0-9][a-z0-9_-]*)")
_ENTIER = re.compile(r"[0-9]{1,19}")
_TYPE_ERREUR = re.compile(r"^((?:[a-z_()]+ ?)+: )?([A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Exit|Interrupt))\b")
log = logging.getLogger("secubox.profiles.validation")

Executer = Callable[[List[str]], Tuple[int, str]]


# ── analyses pures ───────────────────────────────────────────────────────────

def _noms(champ: str) -> List[str]:
    """Noms d'un champ Depends/Recommends : première alternative, sans version ni architecture ni substitution."""
    out = []
    for dep in (champ or "").split(","):
        nom = dep.split("|")[0].strip().split(" ")[0].split("(")[0].split(":")[0].strip()
        if nom and not nom.startswith("$"):
            out.append(nom)
    return out


def lire_dpkg(texte: str) -> Dict[str, Dict[str, Any]]:
    """`dpkg-query -W -f='${Package}\\t${Version}\\t${db:Status-Abbrev}\\t${Depends}\\t${Recommends}\\n'`."""
    out: Dict[str, Dict[str, Any]] = {}
    for ligne in (texte or "").splitlines():
        champs = ligne.split("\t")
        if len(champs) < 3 or not champs[0]:
            continue
        champs += [""] * (5 - len(champs))
        out[champs[0]] = {"version": champs[1] or None, "statut": champs[2].strip(),
                          "depends": _noms(champs[3]), "recommends": _noms(champs[4])}
    return out


def _installe(statut: str) -> bool:
    """Deuxième lettre de db:Status-Abbrev : i (installé) ou un état intermédiaire d'installation ; ni n ni c."""
    return len(statut) >= 2 and statut[1] in "iFUHWt"


def attendus(paquets: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Profil actif (méta-paquet installé le plus haut), et ce qu'il attend : fermeture de ses Depends SecuBox."""
    profils = [m for m in METAS if paquets.get(f"secubox-{m}", {}).get("statut") == "ii"]
    actif = profils[-1] if profils else None
    vus: set = set()
    if actif:
        pile = [f"secubox-{actif}"]
        while pile:
            nom = pile.pop()
            if nom in vus or not NOM_PAQUET.fullmatch(nom):
                continue
            vus.add(nom)
            pile.extend(paquets.get(nom, {}).get("depends", []))
    metas = {f"secubox-{m}" for m in METAS} & vus
    recommandes = {n for m in metas for n in paquets.get(m, {}).get("recommends", []) if NOM_PAQUET.fullmatch(n)}
    return {"profil_actif": actif, "profils_installes": profils, "attendus": vus, "recommandes": recommandes - vus}


def unites_et_modules(liste: str) -> Tuple[List[str], List[str]]:
    """Unités (services et minuteurs, sans gabarit @) et modules /usr/lib/secubox/<nom> livrés par un paquet."""
    unites, modules = set(), set()
    for ligne in (liste or "").splitlines():
        m = _UNITE.fullmatch(ligne.strip())
        if m and "@" not in m.group(1):
            unites.add(m.group(1))
        m = _MODULE.fullmatch(ligne.strip())
        if m:
            modules.add(m.group(1))
    return sorted(unites), sorted(modules)


def lire_show(texte: str) -> Dict[str, Dict[str, str]]:
    """`systemctl show --property=…` de plusieurs unités : blocs séparés par une ligne vide, indexés par Id."""
    out: Dict[str, Dict[str, str]] = {}
    for bloc in (texte or "").split("\n\n"):
        props = dict(ligne.split("=", 1) for ligne in bloc.splitlines() if "=" in ligne)
        if props.get("Id"):
            out[props["Id"]] = props
    return out


def etat_unite(props: Optional[Dict[str, str]], sommeil: bool) -> str:
    """actif | erreur | declenche | non_requis | termine | veille | arrete | inconnu.

    N'est pas « arrêtée » une unité lancée par un minuteur (TriggeredBy), non activée au démarrage, dont la condition de
    démarrage n'est pas remplie (ConditionResult=no : zigbee sans clé, premier-pas déjà fait), ou un oneshot terminé
    avec succès (provisionnements) : c'est leur état normal. Un module à la demande endormi est « en veille »."""
    actif = (props or {}).get("ActiveState", "")
    if actif == "failed":
        return "erreur"
    if actif in ("active", "activating", "reloading", "deactivating"):
        return "actif"
    if actif != "inactive":
        return "inconnu"
    if props.get("TriggeredBy"):
        return "declenche"
    if props.get("UnitFileState") != "enabled" or props.get("ConditionResult") == "no":
        return "non_requis"
    if props.get("Type") == "oneshot" and props.get("Result") == "success":
        return "termine"
    return "veille" if sommeil else "arrete"


def etat_paquet(installe: bool, statut: str, attendu: bool, etats: Iterable[str]) -> str:
    """fonctionnel | veille | arrete | erreur | manquant | absent | inconnu (priorité : l'erreur d'abord)."""
    if not installe:
        return "manquant" if attendu else "absent"
    etats = set(etats)
    if statut != "ii" or "erreur" in etats:
        return "erreur"
    if "arrete" in etats:
        return "arrete"
    if "actif" in etats:
        return "fonctionnel"
    if "veille" in etats:
        return "veille"
    if "inconnu" in etats:
        return "inconnu"
    return "fonctionnel"                                   # sans service propre (pages, bibliothèques, méta-paquets)


def nom_hote(nom: str) -> str:
    """Nom d'hôte tel que le relevé signé l'accepte ([A-Za-z0-9.-], 63 caractères) : jamais un relevé refusé pour un `_`."""
    propre = re.sub(r"[^A-Za-z0-9.-]", "-", str(nom or "")).lstrip(".-")[:63]
    return propre or "box"


def resume_echec(message: str) -> str:
    """Échec de chargement de l'agrégateur réduit à son TYPE (le relevé est signé et servi aux pairs : jamais un chemin,
    jamais une valeur)."""
    m = _TYPE_ERREUR.match(str(message or ""))
    if m:
        return (m.group(1) or "") + m.group(2)
    if "not found" in str(message):
        return "main.py introuvable"
    return "échec de chargement"


def _texte(s: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(s))[:MAX_TEXTE]


def _entier(valeur: Optional[str]) -> Optional[int]:
    """Valeur numérique de systemctl show ; « [not set] » et l'infini (2^64-1) → None."""
    if not valeur or not _ENTIER.fullmatch(valeur):
        return None
    n = int(valeur)
    return n if n < 2 ** 63 else None


# ── collecte ─────────────────────────────────────────────────────────────────

def collecter(*, executer: Executer, lire_liste: Callable[[str], str],
              sante_agregateur: Callable[[], Optional[Dict[str, Any]]], cycles: Optional[Dict[str, str]],
              precedent: Optional[Dict[str, Any]], hostname: str, maintenant: float) -> Dict[str, Any]:
    """Le relevé complet ; chaque sonde est injectée (tests). Ne lève pas : une sonde en échec rend le relevé partiel."""
    partiel: List[str] = []
    if cycles is None:                                    # manifestes illisibles : aucun module tenu pour endormi
        partiel.append("cycles de vie illisibles")
        cycles = {}
    base = {"version": VERSION, "hostname": nom_hote(hostname), "releve_epoch": maintenant,
            "releve_ts": datetime.fromtimestamp(maintenant, timezone.utc).isoformat().replace("+00:00", "Z"),
            "profil_actif": None, "profils_installes": [], "partiel": partiel, "paquets": []}

    rc, sortie = executer(["dpkg-query", "-W",
                           "-f=${Package}\t${Version}\t${db:Status-Abbrev}\t${Depends}\t${Recommends}\n",
                           "secubox-*", "sbxos-*"])
    db = lire_dpkg(sortie) if rc in (0, 1) else {}
    if not db:
        partiel.append("dpkg illisible")
        return base
    a = attendus(db)
    base.update(profil_actif=a["profil_actif"], profils_installes=a["profils_installes"])

    noms = sorted(n for n in ({n for n, d in db.items() if _installe(d["statut"])} | a["attendus"])
                  if NOM_PAQUET.fullmatch(n))[:MAX_PAQUETS]
    livres = {n: unites_et_modules(lire_liste(n)) for n in noms if _installe(db.get(n, {}).get("statut", ""))}
    toutes = sorted({u for unites, _ in livres.values() for u in unites[:MAX_UNITES]})
    show: Dict[str, Dict[str, str]] = {}
    if toutes:
        rc, sortie = executer(["systemctl", "show", "--property=" + ",".join(PROPRIETES), "--", *toutes])
        show = lire_show(sortie) if rc == 0 else {}
        if not show:
            partiel.append("systemctl indisponible")
    sante = sante_agregateur()
    if sante is None:
        partiel.append("agrégateur injoignable")
    montes = set((sante or {}).get("mounted") or [])
    echecs = (sante or {}).get("failed") or {}
    precedents = {p.get("paquet"): p for p in (precedent or {}).get("paquets", []) if isinstance(p, dict)}
    duree = maintenant - float((precedent or {}).get("releve_epoch") or 0)

    for nom in noms:
        d = db.get(nom, {})
        installe = _installe(d.get("statut", ""))
        attendu, recommande = nom in a["attendus"], nom in a["recommandes"]
        meta = nom in {f"secubox-{m}" for m in METAS}
        ligne: Dict[str, Any] = {
            "paquet": nom, "version": d.get("version") if installe else None, "statut_dpkg": d.get("statut") or "absent",
            "installe": installe, "attendu": attendu, "recommande": recommande, "meta": meta,
            "hors_profil": installe and not (attendu or recommande or meta), "unites": [], "agregateur": [],
            "memoire_o": None, "cpu_ns": None, "cpu_pct": None, "erreurs": []}
        erreurs: List[str] = []
        if not installe:
            if attendu:
                erreurs.append(f"attendu par le profil {a['profil_actif']}, non installé")
        else:
            if d.get("statut") != "ii":
                erreurs.append(f"paquet dans l'état dpkg « {d.get('statut')} » (configuration inachevée)")
            unites, modules = livres.get(nom, ([], []))
            memoire = cpu = None
            for u in unites[:MAX_UNITES]:
                props = show.get(u)
                ident = u[len("secubox-"):-len(".service")] if u.startswith("secubox-") and u.endswith(".service") else ""
                etat = etat_unite(props, cycles.get(ident) in SOMMEIL)
                m_o, c_ns = _entier((props or {}).get("MemoryCurrent")), _entier((props or {}).get("CPUUsageNSec"))
                if etat == "actif" and m_o is not None:
                    memoire = (memoire or 0) + m_o
                if c_ns is not None:
                    cpu = (cpu or 0) + c_ns
                if etat == "erreur":
                    erreurs.append(f"{u} en échec ({(props or {}).get('Result') or '?'})")
                ligne["unites"].append({"unite": u, "etat": etat, "memoire_o": m_o if etat == "actif" else None})
            for mod in modules[:MAX_UNITES]:
                if sante is None:
                    ligne["agregateur"].append({"module": mod, "etat": "inconnu"})
                elif mod in montes:
                    ligne["agregateur"].append({"module": mod, "etat": "actif"})
                elif mod in echecs:
                    resume = resume_echec(echecs[mod])
                    ligne["agregateur"].append({"module": mod, "etat": "erreur", "message": resume})
                    erreurs.append(f"agrégateur, module {mod} : {resume}")
            ligne["memoire_o"], ligne["cpu_ns"] = memoire, cpu
            avant = precedents.get(nom, {}).get("cpu_ns")
            if cpu is not None and isinstance(avant, int) and duree > 0 and cpu >= avant:
                ligne["cpu_pct"] = round(100 * (cpu - avant) / (duree * 1e9), 1)
        ligne["erreurs"] = [_texte(e) for e in erreurs[:MAX_ERREURS]]
        ligne["etat"] = etat_paquet(installe, d.get("statut", ""), attendu,
                                    [x["etat"] for x in ligne["unites"] + ligne["agregateur"]])
        base["paquets"].append(ligne)
    return base


# ── entrées / sorties ────────────────────────────────────────────────────────

def ecrire(releve_: Dict[str, Any], chemin: Path) -> None:
    """Écriture atomique : un lecteur (annuaire, l'API) ne voit jamais un fichier à moitié écrit."""
    chemin = Path(chemin)
    tmp = chemin.with_name(chemin.name + ".tmp")
    tmp.write_text(json.dumps(releve_, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, chemin)


def lire(chemin: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    chemin = chemin or chemin_releve()
    try:
        d = json.loads(Path(chemin).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _executer(argv: List[str]) -> Tuple[int, str]:
    try:
        # check=False VOULU : le code de retour est traité par l'appelant (dpkg-query rend 1 si un motif ne trouve rien).
        r = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return 127, ""


def _lire_liste(paquet: str) -> str:
    if not NOM_PAQUET.fullmatch(paquet):
        return ""
    for f in [DPKG_INFO / f"{paquet}.list", *sorted(DPKG_INFO.glob(f"{paquet}:*.list"))]:
        try:
            return f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, chemin: str, timeout: float):
        super().__init__("localhost", timeout=timeout)
        self._chemin = chemin

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._chemin)
        self.sock = s


def _sante_agregateur() -> Optional[Dict[str, Any]]:
    try:
        with contextlib.closing(_UnixHTTP(SOCKET_AGREGATEUR, 10)) as c:
            c.request("GET", "/health")
            r = c.getresponse()
            d = json.loads(r.read()) if r.status == 200 else None
        return d if isinstance(d, dict) else None
    except (OSError, ValueError, http.client.HTTPException) as e:
        log.warning("santé de l'agrégateur illisible : %s", e)
        return None


def _cycles(racine: Path) -> Optional[Dict[str, str]]:
    """Cycle de vie de chaque module ; None (relevé partiel annoncé) si les manifestes ne se lisent pas."""
    from .lifecycle import effective_lifecycle
    from .manifest import ManifestError, load_all
    try:
        return {mid: effective_lifecycle(m) for mid, m in load_all(Path(racine) / "modules.d").items()}
    except (OSError, ValueError, ManifestError) as e:
        log.warning("manifestes des modules illisibles : %s", e)
        return None


def releve(racine: Path = Path("/etc/secubox"), chemin: Optional[Path] = None) -> Dict[str, Any]:
    """Relevé réel de cette box, écrit en `chemin` (défaut : chemin_releve())."""
    chemin = chemin or chemin_releve()
    r = collecter(executer=_executer, lire_liste=_lire_liste, sante_agregateur=_sante_agregateur,
                  cycles=_cycles(racine), precedent=lire(chemin), hostname=socket.gethostname(),
                  maintenant=time.time())
    ecrire(r, chemin)
    return r
