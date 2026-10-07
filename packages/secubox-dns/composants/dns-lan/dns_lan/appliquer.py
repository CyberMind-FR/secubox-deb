# SPDX-License-Identifier: LicenseRef-CMSD-1.0
"""Pose les fichiers générés : sauvegarde, écriture atomique, validation par unbound-checkconf, retour arrière si elle échoue.
Unbound n'est rechargé que si la configuration EFFECTIVE (lignes hors commentaires) change : une mise à jour qui ne touche que les
commentaires ne coupe jamais le DNS. Un seul `generate` à la fois (verrou), et jamais de fichier laissé à moitié posé."""
import contextlib
import fcntl
import os
from pathlib import Path

import secubox_unbound as _unbound          # D4 (#2050) : commande, écriture atomique, checkconf, reload, redémarrage, audit — un seul code
from secubox_unbound import commande as _commande

from . import rendu

AUDIT = Path("/var/log/secubox/audit.log")
VERROU = Path("/run/lock/secubox-dns-lan.lock")
NETWORKCTL = "/usr/bin/networkctl"
NOMS_UNBOUND_GERES = (rendu.F_LAN, rendu.F_IPV6, rendu.F_VUE, rendu.F_HOTES)


class ErreurApplication(RuntimeError):
    """La configuration n'a pas pu être appliquée ; l'état précédent est remis (ou la liste de ce qui n'a pu l'être est donnée)."""


def effectives(texte: str) -> list[str]:
    return [x.strip() for x in texte.splitlines() if x.strip() and not x.strip().startswith("#")]


def _lignes(texte: str | None, debut: str) -> set[str]:
    return {x for x in effectives(texte or "") if x.startswith(debut)}


class Systeme(_unbound.SystemeUnboundRedemarrable):
    """Les effets de bord réels ; les tests injectent un faux. checkconf, reload, redémarrage et audit viennent de secubox_unbound."""
    MODULE = "dns-lan"
    ERREUR = ErreurApplication
    AUDIT = AUDIT

    def recharger_reseau(self) -> None:
        ok, sortie = _commande([NETWORKCTL, "reload"], 60)
        if not ok:
            raise ErreurApplication("networkctl reload a échoué : " + sortie)


@contextlib.contextmanager
def verrou_exclusif(chemin: Path = VERROU, attendre: bool = True):
    chemin.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(chemin, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if attendre else fcntl.LOCK_NB))
        except BlockingIOError:
            raise ErreurApplication("un autre secubox-dns-lan est en cours") from None
        yield
    finally:
        os.close(fd)


def _lire(chemin: Path) -> str | None:
    try:
        return chemin.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None


def _ecrire_atomique(chemin: Path, texte: str) -> None:
    _unbound.ecrire_atomique(chemin, texte, 0o644, prefixe=".dns-lan-", erreur=ErreurApplication)


def _est_unbound(chemin: str, cfg: dict) -> bool:
    return Path(chemin).parent == Path(cfg["dossier"])


def _orphelins(cfg: dict, voulu: dict) -> list[str]:
    """Fichiers Unbound que CE paquet a générés (marque présente) et que le TOML ne produit plus : une section retirée doit
    arrêter la redirection. Un fichier posé à la main (sans marque) n'est jamais touché."""
    d = Path(cfg["dossier"])
    sortie = []
    for nom in NOMS_UNBOUND_GERES:
        c = str(d / nom)
        if c in voulu:
            continue
        t = _lire(d / nom)
        if t is not None and rendu.MARQUE in t:
            sortie.append(c)
    return sortie


def deriver(cfg: dict) -> list[str]:
    """Chemins dont le contenu effectif sur disque diffère de ce que le TOML produirait (y compris un fichier généré devenu orphelin)."""
    voulu = rendu.rendre(cfg)
    ecart = []
    for chemin, texte in voulu.items():
        actuel = _lire(Path(chemin))
        if actuel is None or effectives(actuel) != effectives(texte):
            ecart.append(chemin)
    return ecart + _orphelins(cfg, voulu)


def _ancetres_manquants(p: Path) -> list[Path]:
    manquants = []
    d = p.parent
    while not d.exists() and d != d.parent:
        manquants.append(d)
        d = d.parent
    return manquants


def _restaurer(avant: dict, crees_dossiers: list[Path]) -> list[str]:
    """Remet l'état précédent octet pour octet ; chaque fichier est traité même si un autre échoue. Renvoie ce qui n'a pu l'être."""
    echecs = []
    for c, ancien in avant.items():
        p = Path(c)
        try:
            if ancien is None:
                p.unlink(missing_ok=True)
            elif _lire(p) != ancien:
                _ecrire_atomique(p, ancien)
        except (OSError, ErreurApplication) as e:
            echecs.append(f"{p.name} ({e})")
    for d in crees_dossiers:
        with contextlib.suppress(OSError):
            d.rmdir()
    return echecs


def generer(cfg: dict, systeme: Systeme | None = None, verrou: Path = VERROU) -> dict:
    with verrou_exclusif(verrou):
        return _generer(cfg, systeme or Systeme())


def _generer(cfg: dict, s: Systeme) -> dict:
    voulu = rendu.rendre(cfg)
    orphelins = _orphelins(cfg, voulu)
    avant = {c: _lire(Path(c)) for c in list(voulu) + orphelins}
    ecrits = [c for c, t in voulu.items() if avant[c] != t]
    if not ecrits and not orphelins:
        return {"ecrits": [], "supprimes": [], "recharge_unbound": False, "recharge_reseau": False}
    apres = {c: voulu.get(c) for c in avant}                                     # None = supprimé
    effectif = [c for c in avant if (avant[c] is None) != (apres[c] is None)
                or (avant[c] is not None and effectives(avant[c]) != effectives(apres[c] or ""))]
    recharge_unbound = any(_est_unbound(c, cfg) for c in effectif)
    recharge_reseau = any(not _est_unbound(c, cfg) for c in effectif)
    # `unbound-control reload` ne rouvre pas les sockets : une écoute nouvelle (interface:) ou ip-freebind exige un redémarrage.
    ecoutes_avant = _lignes("\n".join(avant[c] or "" for c in avant if _est_unbound(c, cfg)), "interface:")
    ecoutes_apres = _lignes("\n".join(apres[c] or "" for c in apres if _est_unbound(c, cfg)), "interface:")
    redemarrer = bool(ecoutes_apres - ecoutes_avant) or (
        "ip-freebind: yes" in _lignes("\n".join(apres[c] or "" for c in apres if _est_unbound(c, cfg)), "ip-freebind")
        and "ip-freebind: yes" not in _lignes("\n".join(avant[c] or "" for c in avant if _est_unbound(c, cfg)), "ip-freebind"))
    crees: list[Path] = []
    try:
        for c in ecrits:
            p = Path(c)
            for d in _ancetres_manquants(p):
                if d not in crees:
                    crees.append(d)
            p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            for d in crees:
                if d.exists():
                    os.chmod(d, 0o755)
            _ecrire_atomique(p, voulu[c])
        for c in orphelins:
            Path(c).unlink(missing_ok=True)
        if any(_est_unbound(c, cfg) for c in list(ecrits) + orphelins):
            ok, sortie = s.verifier_unbound()
            if not ok:
                raise ErreurApplication("unbound-checkconf refuse la configuration : " + sortie)
    except (ErreurApplication, OSError) as e:
        echecs = _restaurer(avant, crees)
        if echecs:
            s.audit("generate-echec-restauration", f"{e} ; non restaurés : {', '.join(echecs)}"[:290])
            raise ErreurApplication(f"{e} ; restauration INCOMPLÈTE : {', '.join(echecs)}") from e
        s.audit("generate-refuse", str(e)[:290])
        raise e if isinstance(e, ErreurApplication) else ErreurApplication(f"écriture impossible : {e}") from e
    try:
        if recharge_unbound:
            s.redemarrer_unbound() if redemarrer else s.recharger_unbound()
        if recharge_reseau:
            s.recharger_reseau()
    except (ErreurApplication, OSError) as e:
        echecs = _restaurer(avant, crees)                                        # les fichiers repartent avec ce qui tourne encore
        s.audit("generate-rechargement-echoue", f"{e}" + (f" ; non restaurés : {', '.join(echecs)}" if echecs else ""))
        raise e if isinstance(e, ErreurApplication) else ErreurApplication(str(e)) from e
    action = "redémarre" if recharge_unbound and redemarrer else ("recharge" if recharge_unbound else "inchange")
    s.audit("generate", f"ecrits={len(ecrits)} supprimes={len(orphelins)} unbound={action} reseau={'recharge' if recharge_reseau else 'inchange'}")
    return {"ecrits": ecrits, "supprimes": orphelins, "recharge_unbound": recharge_unbound, "recharge_reseau": recharge_reseau}
