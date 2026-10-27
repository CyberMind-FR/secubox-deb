# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""secubox_unbound — l'unique endroit qui écrit une vue Unbound, la valide, la recharge et revient en arrière (D4, #2050).

POURQUOI. webfilter-ctl et dns-lan portaient chacun leur copie des mêmes gestes : lancer une commande avec délai, écrire un fichier de façon atomique,
`unbound-checkconf`, `unbound-control reload`, une ligne d'audit. Deux copies d'un code qui coupe la résolution de tout le réseau quand il se trompe,
c'est deux endroits où le corriger — et un troisième auteur (ad-guard, vortex-dns) qui allait écrire la sienne.

STDLIB SEULEMENT, AUCUN EFFET DE BORD À L'IMPORT. Cette bibliothèque est chargée par des assistants root sous AppArmor : elle ne doit tirer ni FastAPI,
ni la configuration, ni les secrets (c'est pourquoi elle n'est PAS un sous-module de `secubox_core`, dont le `__init__` importe tout cela).

CE QUI RESTE CHEZ L'APPELANT : le contenu de la vue (zones, profils, listes), le verrou propre à son état, ses règles de sécurité (propriétaire du
dossier d'état, plafonds de taille). La bibliothèque ne connaît que le geste « poser ce texte à cet endroit, vérifier, recharger, sinon revenir ».
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CHECKCONF = "/usr/sbin/unbound-checkconf"      # chemins absolus : outil lancé en root, jamais de PATH ni de variable d'environnement
CONTROL = "/usr/sbin/unbound-control"
SYSTEMCTL = "/usr/bin/systemctl"
AUDIT = Path("/var/log/secubox/audit.log")     # ajout seul
# unbound-checkconf relit TOUTE la configuration, drop-ins compris : sur gk2, ~820 000 zones (webfilter) + ~400 000 (adblock)
# + ~160 000 (adulte) prennent 23 s à vide et plusieurs minutes quand la carte est chargée (charge 20, deux rechargements qui
# coïncident). Un budget de 60 s faisait REFUSER une configuration valide — l'appelant restaurait l'ancienne et l'appareil
# gardait sa vue périmée (#2979, #3005). Le refus doit venir de checkconf, jamais du chronomètre : 10 min.
DELAI_CHECKCONF = 600


class ErreurUnbound(RuntimeError):
    """La vue n'a pas pu être posée ; l'état précédent est remis."""


def commande(args: list[str], delai: int) -> tuple[bool, str]:
    """Lance une commande avec un délai ; rend (succès, fin de la sortie). Ne lève jamais : un outil absent ou trop lent est un échec."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=delai, check=False)
    except subprocess.TimeoutExpired:
        return False, f"{Path(args[0]).name} : délai de {delai} s dépassé"
    except OSError as e:
        return False, f"{Path(args[0]).name} : {e}"
    return r.returncode == 0, (r.stdout + r.stderr).strip()[-300:]


def fsync_dossier(d: Path | str) -> None:
    """Rend durable le renommage lui-même (best-effort : un dossier illisible ne fait pas échouer l'écriture)."""
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def ecrire_atomique(chemin: Path | str, texte: str, mode: int = 0o644, prefixe: str = ".sbx-", erreur: type = ErreurUnbound) -> None:
    """Écrit puis remplace : le lecteur voit l'ancien fichier ou le nouveau, jamais un fichier à moitié écrit. Rien ne reste en cas d'échec.

    Refuse d'écrire à travers un lien symbolique (le dossier d'une vue Unbound est lisible par d'autres comptes : un lien posé là ferait écrire
    n'importe où à un processus root). `erreur` : la classe levée, pour que les `except` de l'appelant restent valides."""
    chemin = Path(chemin)
    if chemin.is_symlink():
        raise erreur(f"{chemin} est un lien symbolique : refusé")
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=chemin.parent, prefix=prefixe)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(texte)
            f.flush()
            os.fchmod(f.fileno(), mode)
            os.fsync(f.fileno())
        os.replace(tmp, chemin)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    fsync_dossier(chemin.parent)


class SystemeUnbound:
    """Les effets de bord réels sur Unbound. Les tests des appelants en injectent un faux.

    Un appelant le sous-classe pour poser SON nom (MODULE, repris dans l'audit) et SA classe d'erreur (ERREUR, pour que ses `except` restent valides)."""
    MODULE = "unbound"
    ERREUR = ErreurUnbound
    AUDIT = AUDIT

    def verifier_unbound(self) -> tuple[bool, str]:
        return commande([CHECKCONF], DELAI_CHECKCONF)

    def recharger_unbound(self) -> None:
        ok, sortie = commande([CONTROL, "reload"], 120)
        if not ok:
            raise self.ERREUR("unbound-control reload a échoué : " + sortie)

    def audit(self, action: str, detail: str = "") -> None:
        try:
            with open(self.AUDIT, "a", encoding="utf-8") as f:                    # ajout seul
                f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "module": self.MODULE,
                                    "action": action, "detail": detail[:300]}, ensure_ascii=False) + "\n")
        except OSError as e:                                                      # ne bloque pas l'opération, mais ne se tait pas
            print(f"secubox-{self.MODULE} : audit non écrit ({action}) : {e}", file=sys.stderr)


class SystemeUnboundRedemarrable(SystemeUnbound):
    """Pour les SEULS appelants qui ont une raison de redémarrer Unbound (une écoute nouvelle). Les autres n'héritent PAS de cette capacité :
    un assistant de listes ne doit jamais pouvoir couper la résolution en redémarrant le service."""

    def redemarrer_unbound(self) -> None:
        """`reload` ne rouvre pas les sockets : une écoute nouvelle (interface:, ip-freebind) exige un redémarrage."""
        ok, sortie = commande([SYSTEMCTL, "restart", "unbound"], 120)
        if not ok:
            raise self.ERREUR("redémarrage d'unbound refusé : " + sortie)


def _restaurer(chemin: Path, ancien: bytes | None) -> None:
    if ancien is None:
        chemin.unlink(missing_ok=True)
    else:
        tmp = chemin.parent / (".sbx-restaure-" + chemin.name)
        tmp.write_bytes(ancien)
        os.replace(tmp, chemin)


def _lire_octets(chemin: Path) -> bytes | None:
    try:
        return chemin.read_bytes()
    except FileNotFoundError:
        return None


def ecrire_verifier(chemin: Path | str, texte: str, systeme: SystemeUnbound | None = None, mode: int = 0o644) -> str:
    """Pose `texte` dans `chemin` et VÉRIFIE la configuration, SANS recharger : l'appelant décide du rechargement (ad-guard TV applique certaines
    règles à chaud, sans recharger). Si la vérification refuse, remet l'ancien contenu octet pour octet et lève ERREUR.

    Rend « inchange » (fichier identique, rien n'est écrit ni vérifié) ou « ecrit »."""
    s = systeme or SystemeUnbound()
    chemin = Path(chemin)
    ancien = _lire_octets(chemin)
    if ancien is not None and ancien == texte.encode("utf-8"):
        return "inchange"
    ecrire_atomique(chemin, texte, mode, erreur=s.ERREUR)
    ok, sortie = s.verifier_unbound()
    if not ok:
        _restaurer(chemin, ancien)
        raise s.ERREUR("unbound-checkconf refuse la configuration : " + sortie)
    return "ecrit"


def poser_vue(chemin: Path | str, texte: str, systeme: SystemeUnbound | None = None, mode: int = 0o644) -> str:
    """Pose `texte` dans `chemin`, vérifie la configuration, recharge Unbound ; au moindre échec, remet l'ancien contenu OCTET POUR OCTET.

    Rend « inchange » (aucun rechargement : un fichier identique ne dérange pas la résolution) ou « applique ». Lève ErreurUnbound (ou la classe
    ERREUR du système) sur un échec, après restauration."""
    s = systeme or SystemeUnbound()
    chemin = Path(chemin)
    ancien = _lire_octets(chemin)
    if ecrire_verifier(chemin, texte, s, mode) == "inchange":
        return "inchange"
    try:
        s.recharger_unbound()
    except BaseException:
        _restaurer(chemin, ancien)
        with contextlib.suppress(Exception):
            s.recharger_unbound()          # Unbound garde la NOUVELLE vue en mémoire tant qu'on ne lui a pas fait relire l'ancienne
        raise
    return "applique"


def _signaler_retour(s: SystemeUnbound, e: BaseException, echecs: list) -> None:
    """Un retour arrière incomplet (disque plein, second rechargement refusé) laisse un état mélangé : il est audité et dit
    dans l'erreur, jamais tu (l'ancien webfilter-ctl le disait déjà)."""
    if not echecs:
        return
    detail = " ; ".join(echecs)
    with contextlib.suppress(Exception):
        s.audit("restauration-echouee", detail[:280])
    if isinstance(e, Exception):
        raise s.ERREUR(f"{e} ; retour arrière INCOMPLET : {detail}"[:600]) from e


def poser_vues(changements: dict, systeme: SystemeUnbound | None = None, mode: int = 0o644, forcer: bool = False) -> str:
    """Pose plusieurs fichiers (texte) et en retire d'autres (None) en UNE transaction : une vérification, un rechargement ; au
    moindre échec, TOUS sont remis octet pour octet (#3205 : 92-secubox-listes.conf remplace trois fichiers à la fois — un
    état intermédiaire chargerait les mêmes zones deux fois). Rend « inchange » (rien d'écrit ni de rechargé) ou « applique ».

    `forcer` : vérifier et recharger même si tout est déjà en place (une passe précédente tuée après la bascule)."""
    s = systeme or SystemeUnbound()
    voulu = {Path(p): t for p, t in changements.items()}
    anciens = {p: _lire_octets(p) for p in voulu}
    if not forcer and all(anciens[p] == (t.encode("utf-8") if t is not None else None) for p, t in voulu.items()):
        return "inchange"

    def tout_remettre() -> list:
        echecs = []
        for p, a in anciens.items():
            try:
                _restaurer(p, a)
            except OSError as e:
                echecs.append(f"{p.name} non remis ({e.strerror or e})")
        return echecs

    try:
        for p, t in voulu.items():
            if t is None:
                p.unlink(missing_ok=True)
            elif anciens[p] != t.encode("utf-8"):
                ecrire_atomique(p, t, mode, erreur=s.ERREUR)
        ok, sortie = s.verifier_unbound()
        if not ok:
            raise s.ERREUR("unbound-checkconf refuse la configuration : " + sortie)
    except BaseException as e:
        _signaler_retour(s, e, tout_remettre())
        raise
    try:
        s.recharger_unbound()
    except BaseException as e:
        echecs = tout_remettre()
        try:
            s.recharger_unbound()          # Unbound garde la NOUVELLE configuration en mémoire tant qu'on ne lui a pas fait relire l'ancienne
        except Exception as e2:
            echecs.append(f"second rechargement : {e2}")
        _signaler_retour(s, e, echecs)
        raise
    return "applique"


def retirer_vue(chemin: Path | str, systeme: SystemeUnbound | None = None) -> str:
    """Supprime une vue, vérifie la configuration restante, recharge. Si la vérification refuse, la vue est remise. « absent » si elle n'existait pas
    (aucun rechargement)."""
    s = systeme or SystemeUnbound()
    chemin = Path(chemin)
    ancien = _lire_octets(chemin)
    if ancien is None:
        return "absent"
    chemin.unlink()
    ok, sortie = s.verifier_unbound()
    if not ok:
        _restaurer(chemin, ancien)
        raise s.ERREUR("unbound-checkconf refuse la configuration : " + sortie)
    try:
        s.recharger_unbound()
    except BaseException:
        _restaurer(chemin, ancien)
        with contextlib.suppress(Exception):
            s.recharger_unbound()
        raise
    return "retire"
