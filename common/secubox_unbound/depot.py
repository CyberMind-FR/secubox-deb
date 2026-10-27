# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox_unbound.depot — les SOURCES des listes DNS et leur application par secubox-dns-listes (#3205).

Les générateurs (webfilter-ctl, adblock-sync, adult-sync) déposent leur rendu INCHANGÉ dans `SOURCES` (`deposer_source`) et
s'arrêtent là : leurs droits se réduisent à ce dépôt, et un clic dans webfilter n'attend pas la compilation. Le service
root secubox-dns-listes (déclenché par secubox-dns-listes.path) appelle `appliquer` : il adopte un ancien fichier encore
présent dans unbound.conf.d, compile (ou recopie en mode « direct »), pose 92-secubox-listes.conf et retire les anciens
fichiers en UNE transaction (`poser_vues`), puis note l'état dans `ETAT`.

Le .path surveille aussi unbound.conf.d (une vue TV ou un réseau ajouté change les classes de clients) ; c'est l'empreinte
des ENTRÉES, notée avec l'état, qui évite de recompiler pour rien — y compris après les propres écritures du service, ou
après un échec sur les mêmes entrées.

L'ARBRE EST À ROOT, À PART (relecture #3205) : /var/lib/secubox appartient au compte partagé `secubox`, qui pourrait renommer
un sous-dossier root et le remplacer par le sien (sources forgées compilées par root, écriture d'un générateur root à travers
un lien). /var/lib/secubox-dns-listes est root 0755, et chaque écriture vérifie le dossier ET son parent. STDLIB SEULEMENT."""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Optional

from . import CONTROL, ErreurUnbound, SystemeUnbound, commande, ecrire_atomique, poser_vues
from . import listes

RACINE = Path("/var/lib/secubox-dns-listes")
SOURCES = RACINE / "sources"
ETAT = RACINE / "etat.json"
VERROU = RACINE / "verrou"               # 0600 dans l'arbre root : /run/lock (1777) laissait tout compte local bloquer le service
CONF_D = Path("/etc/unbound/unbound.conf.d")
REGLAGES = Path("/etc/secubox/dns-listes.toml")
MODES = ("compile", "direct")
REESSAI_S = 3600          # un échec sur les MÊMES entrées n'est retenté qu'après ce délai (minuterie quotidienne, ou entrée nouvelle)
PASSES_MAX = 3            # une source déposée PENDANT la compilation est reprise (systemd ne relance pas une unité active)
_CODE = (Path(listes.__file__), Path(__file__))     # une mise à jour du compilateur impose de recompiler


class ErreurDepot(ErreurUnbound):
    """Une source refusée (nom inconnu, lien symbolique, dossier qui n'est pas sûr)."""


class SystemeListes(SystemeUnbound):
    """Les effets de bord de secubox-dns-listes. `unbound-control reload` rend la main dès le signal accepté, PAS quand la
    configuration est chargée (#2969, une bonne minute sur gk2) : l'application n'est réussie que lorsqu'Unbound répond de
    nouveau à `unbound-control status`. Sinon ERREUR, et `poser_vues` remet l'ancienne configuration. Aucun redémarrage."""
    MODULE = "dns-listes"
    ATTENTE_S = 300
    PAS_S = 2

    def recharger_unbound(self) -> None:
        super().recharger_unbound()
        fin = time.monotonic() + self.ATTENTE_S
        while True:
            ok, sortie = commande([CONTROL, "status"], 30)
            if ok:
                return
            if time.monotonic() >= fin:
                raise self.ERREUR(f"Unbound ne répond plus {self.ATTENTE_S} s après le rechargement : {sortie}"[:300])
            time.sleep(self.PAS_S)


def _dossier_sur(d: Path) -> None:
    """Un vrai dossier (pas un lien), du compte qui écrit (root en production), fermé en écriture au groupe et aux autres."""
    try:
        st = os.lstat(d)
    except OSError as e:
        raise ErreurDepot(f"dossier {d} inutilisable ({e.strerror})") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
        raise ErreurDepot(f"dossier {d} refusé : lien symbolique, autre propriétaire ou ouvert en écriture")


def preparer_sources(sources: Path = SOURCES) -> Path:
    """Le dossier des sources et son parent, vérifiés (le dossier est créé fermé s'il manque)."""
    sources = Path(sources)
    _dossier_sur(sources.parent)
    if not os.path.lexists(sources):
        with contextlib.suppress(FileExistsError):
            os.mkdir(sources, 0o755)
            os.chmod(sources, 0o755)                   # sous UMask=0027 il naîtrait 0750 : l'API ad-guard date la source
    _dossier_sur(sources)
    return sources


def _chemin_source(nom: str, sources: Path) -> Path:
    if nom not in listes.SOURCES_CONNUES:
        raise ErreurDepot(f"source inconnue : {nom!r} (attendu : {', '.join(listes.SOURCES_CONNUES)})")
    p = Path(sources) / nom
    if p.is_symlink():
        raise ErreurDepot(f"{p} est un lien symbolique : refusé")
    return p


def deposer_source(nom: str, texte: str, sources: Path = SOURCES) -> str:
    """Le rendu d'un générateur, déposé tel quel. « inchange » ou « depose » (secubox-dns-listes.path déclenche la suite)."""
    p = _chemin_source(nom, preparer_sources(sources))
    try:
        if p.read_text(encoding="utf-8") == texte:
            return "inchange"
    except FileNotFoundError:
        pass
    ecrire_atomique(p, texte, 0o644, erreur=ErreurDepot)
    return "depose"


def retirer_source(nom: str, sources: Path = SOURCES) -> str:
    """Le générateur ne bloque plus rien : sa source disparaît. « absent » ou « retire »."""
    p = _chemin_source(nom, preparer_sources(sources))
    if not p.exists():
        return "absent"
    p.unlink()
    return "retire"


def lire_mode(reglages: Path = REGLAGES) -> str:
    """`mode = "compile"` (défaut) ou `"direct"` (sources recopiées telles quelles, sans compilation : retour arrière)."""
    try:
        import tomllib
        with open(reglages, "rb") as f:
            m = tomllib.load(f).get("mode", "compile")
    except FileNotFoundError:
        return "compile"
    except (OSError, ValueError) as e:
        print(f"secubox-dns-listes : {reglages} illisible ({e}) : mode « compile »", file=sys.stderr)
        return "compile"
    if m not in MODES:
        print(f"secubox-dns-listes : mode {m!r} inconnu : mode « compile »", file=sys.stderr)
        return "compile"
    return m


def _prendre_verrou(chemin: Path) -> int:
    """Fichier 0600 ouvert sans suivre de lien : aucun autre compte ne peut le tenir."""
    fd = os.open(chemin, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _noter(etat: Path, d: dict) -> dict:
    d = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **d}
    try:
        ecrire_atomique(etat, json.dumps(d, ensure_ascii=False, indent=1), 0o644)
    except (OSError, ErreurUnbound) as e:
        print(f"secubox-dns-listes : état non écrit ({e})", file=sys.stderr)
    return d


def lire_etat(etat: Path = ETAT) -> Optional[dict]:
    try:
        d = json.loads(Path(etat).read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _stat(p: Path) -> Optional[list]:
    try:
        s = p.stat()
    except OSError:
        return None
    return [s.st_size, s.st_mtime_ns]


def fichiers_contexte(conf_d: Path) -> list:
    """Ce qu'Unbound inclut (`*.conf`, fichiers cachés exclus : `.sbx-restaure-*` d'une remise en place interrompue), hors
    sources et sortie."""
    return [p for p in sorted(conf_d.glob("*.conf"))
            if not p.name.startswith(".") and p.name not in listes.SOURCES_CONNUES and p.name != listes.SORTIE]


def _entrees(sources: Path, conf_d: Path, mode: str) -> dict:
    """Ce dont dépend le résultat : mode, code du compilateur, sources (déposées par écriture atomique : taille et date
    suffisent), et ce que le compilateur lit du contexte."""
    return {"mode": mode, "code": [_stat(p) for p in _CODE],
            "sources": {n: _stat(sources / n) for n in listes.SOURCES_CONNUES},
            "contexte": listes.empreinte(fichiers_contexte(conf_d))}


def _poses(conf_d: Path) -> dict:
    return {n: _stat(conf_d / n) for n in (*listes.SOURCES_CONNUES, listes.SORTIE)}


def _signature(sources: Path, conf_d: Path, mode: str) -> dict:
    """Les entrées ET ce qui est posé : un 92 retiré à la main, ou un ancien fichier réécrit, n'est pas « à jour »."""
    return {**_entrees(sources, conf_d, mode), "poses": _poses(conf_d)}


def _adopter(sources: Path, conf_d: Path) -> list:
    """Un ancien fichier dans unbound.conf.d (installation d'avant, ou générateur pas encore mis à jour) devient la source
    s'il n'y en a pas, ou s'il est plus récent qu'elle."""
    adoptes = []
    for nom in listes.SOURCES_CONNUES:
        ancien = conf_d / nom
        if ancien.is_file() and not ancien.is_symlink():
            src = _chemin_source(nom, sources)
            if not src.exists() or ancien.stat().st_mtime > src.stat().st_mtime:
                texte = ancien.read_text(encoding="utf-8")
                if not src.exists() or src.read_text(encoding="utf-8") != texte:
                    ecrire_atomique(src, texte, 0o644, erreur=ErreurDepot)
                    adoptes.append(nom)
    return adoptes


def _passe(s: SystemeUnbound, mode: str, sources: Path, conf_d: Path, forcer: bool = False) -> tuple:
    presentes = [sources / n for n in listes.SOURCES_CONNUES if (sources / n).is_file()]
    stats: dict = {}
    changements: dict = {}
    if mode == "direct":
        for p in presentes:                       # retour arrière, mais pas un passe-droit : mêmes directives permises qu'à la compilation
            listes.lire([p], sources=[p.name])
        for n in listes.SOURCES_CONNUES:
            changements[conf_d / n] = (sources / n).read_text(encoding="utf-8") if (sources / n) in presentes else None
        changements[conf_d / listes.SORTIE] = None
    else:
        if presentes:
            texte, stats = listes.compiler(presentes, fichiers_contexte(conf_d))
            changements[conf_d / listes.SORTIE] = texte
        else:
            changements[conf_d / listes.SORTIE] = None
        for n in listes.SOURCES_CONNUES:
            changements[conf_d / n] = None
    return poser_vues(changements, s, forcer=forcer), stats, len(presentes)


def appliquer(systeme: Optional[SystemeUnbound] = None, sources: Path = SOURCES, conf_d: Path = CONF_D, etat: Path = ETAT,
              reglages: Path = REGLAGES, verrou: Path = VERROU, maintenant=time.time) -> dict:
    """Une passe complète ; ne lève pas : le résultat (et l'erreur éventuelle) est rendu ET noté dans `etat`.

    La signature notée est celle des entrées que la dernière passe a COMPILÉES (plus ce qui est posé) : un dépôt arrivé
    pendant la passe, que systemd ne signale plus une fois l'unité active, se voit au passage suivant. « en-cours » est
    noté avant la bascule : un processus tué (OOM, délai) laisse cette marque, et la passe suivante vérifie et recharge
    même si les fichiers sont déjà en place."""
    s = systeme or SystemeListes()
    sources, conf_d = Path(sources), Path(conf_d)
    if not conf_d.is_dir():
        return {"etat": "sans-unbound", "mode": lire_mode(reglages)}
    mode = lire_mode(reglages)
    try:
        fd = _prendre_verrou(verrou)
    except OSError as e:
        maintenant_s = int(maintenant())
        return _noter(etat, {"etat": "erreur", "mode": mode, "erreur": f"verrou {verrou} inutilisable ({e.strerror})",
                             "signature": None, "t": maintenant_s, "t_echec": maintenant_s})
    try:
        return _appliquer_tenu(s, sources, conf_d, etat, mode, maintenant)
    finally:
        os.close(fd)


def _appliquer_tenu(s: SystemeUnbound, sources: Path, conf_d: Path, etat: Path, mode: str, maintenant) -> dict:
    precedent = lire_etat(etat) or {}
    interrompu = precedent.get("etat") == "en-cours"
    adoptes: list = []
    avant = None
    try:
        preparer_sources(sources)
        adoptes = _adopter(sources, conf_d)
        sig = _signature(sources, conf_d, mode)
        if not interrompu and precedent.get("signature") == sig:
            if precedent.get("etat") in ("applique", "inchange"):
                return _noter(etat, {**{k: precedent[k] for k in ("stats", "passes") if k in precedent},
                                     "etat": "inchange", "mode": mode, "adoptes": [], "signature": sig,
                                     "t": int(maintenant())})
            t_echec = precedent.get("t_echec")
            if precedent.get("etat") == "erreur" and isinstance(t_echec, int) and maintenant() - t_echec < REESSAI_S:
                return _noter(etat, {**precedent, "t": int(maintenant())})       # mêmes entrées, même échec : pas avant REESSAI_S
        _noter(etat, {"etat": "en-cours", "mode": mode, "adoptes": adoptes, "t": int(maintenant())})
        applique, stats, nb, passes = False, {}, 0, 0
        while True:
            passes += 1
            avant = _entrees(sources, conf_d, mode)
            r, stats, nb = _passe(s, mode, sources, conf_d, forcer=interrompu)
            interrompu = False
            applique = applique or r == "applique"
            if passes >= PASSES_MAX or _entrees(sources, conf_d, mode) == avant:
                break
    except (listes.ErreurListes, ErreurUnbound, s.ERREUR, OSError, ValueError) as e:
        with contextlib.suppress(Exception):
            s.audit("listes-erreur", f"mode={mode} : {e}"[:280])
        sig_echec = None
        if avant is not None:
            with contextlib.suppress(OSError):
                sig_echec = {**avant, "poses": _poses(conf_d)}
        maintenant_s = int(maintenant())
        return _noter(etat, {"etat": "erreur", "mode": mode, "erreur": str(e)[:500], "adoptes": adoptes,
                             "signature": sig_echec, "t": maintenant_s, "t_echec": maintenant_s})
    if applique:
        s.audit("listes", f"mode={mode} sources={nb} emis={stats.get('emis', '-')} "
                          f"avant={stats.get('zones_chargees_avant', '-')} adoptes={','.join(adoptes) or '-'} passes={passes}")
    return _noter(etat, {"etat": "applique" if applique else "inchange", "mode": mode, "stats": stats, "adoptes": adoptes,
                         "passes": passes, "signature": {**avant, "poses": _poses(conf_d)}, "t": int(maintenant())})
