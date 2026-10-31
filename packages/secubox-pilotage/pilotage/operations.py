# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""
SecuBox-Deb :: pilotage :: catalogue d'actions du maître et suivi des fins (#3126 L2 tâche 6)

Catalogue FERMÉ : une action de l'API (`POST /boxes/{x}/actions/{action}`) correspond à une commande Operate de l'agent
et à ses paramètres exacts. `forte` : la page doit faire retaper le nom de la box (confirmation vérifiée par l'API) sur
une box du propriétaire ; sur une box cliente, l'accord du détenteur, donné sur la box, en tient lieu.

`Suivi` reçoit du canal la PREMIÈRE fin d'un job (X_SECUBOX_OperationDone, dédoublonnée par le stockage), l'audite
(`pilotage_action_resultat`), puis lance la suite : après un `renommer` réussi sur une box du maillage, le code de
jonction lié au nouveau nom part par `Device.X_SECUBOX_Maillage.Rejoindre()` (R-L2-35). Le code ne passe que par la file
de la box : jamais dans un journal, l'audit ou la base.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .identite import Box
from .renommage import ErreurRejoindre, envoyer_rejoindre, nouveau_nom

log = logging.getLogger("pilotage.operations")

RE_UNITE = re.compile(r"secubox-[a-z0-9][a-z0-9@.-]{0,62}\.(service|timer)")     # motif de l'agent et du ctl
RE_NOM = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")                          # libellé DNS
RE_IDENT = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")                                   # identifiant de session de support
RE_ACTEUR = re.compile(r"[a-z_][a-z0-9_.-]{0,63}")                                  # R-L2-14 : motif exigé par l'agent
DELAI_REJOINDRE_S = 120.0
JOURNAL_ORPHELINES_S = 60.0   # fins de jobs inconnus : une ligne de journal agrégée par box et par minute au plus, jamais d'audit


@dataclass(frozen=True)
class Action:
    commande: str
    parametres: tuple = ()            # clés attendues dans `args`, toutes obligatoires
    forte: bool = False               # confirmation forte sur une box du propriétaire
    fixes: tuple = ()                 # paramètres posés par le maître (clé, valeur)


CATALOGUE = {
    "reboot": Action("Device.Reboot()", forte=True),
    "maj-paquets": Action("Device.X_SECUBOX_Packages.MettreAJour()"),
    # #3338 : une app de la boutique du maître installée sur une box du parc (installation seulement, côté box)
    "installer": Action("Device.X_SECUBOX_Packages.Installer()", ("paquet",), forte=True),
    "service-demarrer": Action("Device.X_SECUBOX_Services.Agir()", ("unite",), fixes=(("action", "demarrer"),)),
    "service-arreter": Action("Device.X_SECUBOX_Services.Agir()", ("unite",), forte=True, fixes=(("action", "arreter"),)),
    "service-redemarrer": Action("Device.X_SECUBOX_Services.Agir()", ("unite",), fixes=(("action", "redemarrer"),)),
    "renommer": Action("Device.X_SECUBOX_Nom.Renommer()", ("nom",), forte=True),
    "renouveler": Action("Device.X_SECUBOX_Secrets.Renouveler()", forte=True),
    # #3302 : bascule d'interface (profil léger « distante » de la box, ou retour au profil d'avant)
    "interface-distante": Action("Device.X_SECUBOX_Pilotage.Interface.Basculer()", forte=True, fixes=(("sens", "distante"),)),
    "interface-locale": Action("Device.X_SECUBOX_Pilotage.Interface.Basculer()", forte=True, fixes=(("sens", "locale"),)),
}
RE_PAQUET = re.compile(r"secubox-[a-z0-9][a-z0-9-]{0,47}")                          # motif de l'agent et du ctl (#3338)
_MOTIFS = {"unite": RE_UNITE, "nom": RE_NOM, "paquet": RE_PAQUET}

COMMANDE_SUPPORT_OUVRIR = "Device.X_SECUBOX_Support.Ouvrir()"
COMMANDE_SUPPORT_FERMER = "Device.X_SECUBOX_Support.Fermer()"
COMMANDE_CONFIRMER = "Device.X_SECUBOX_Pilotage.Interface.Confirmer()"
DELAI_CONFIRMER_S = 120.0


def arguments(action: Action, args: dict) -> Optional[dict]:
    """Les paramètres à envoyer à l'agent, ou None si `args` n'a pas exactement les clés attendues, de la bonne forme."""
    if not isinstance(args, dict) or set(args) != set(action.parametres):
        return None
    for k in action.parametres:
        v = args[k]
        if not isinstance(v, str) or len(v) > 255 or not _MOTIFS[k].fullmatch(v):
            return None
    return {**args, **dict(action.fixes)}


def corps_operate(commande: str, args: dict, acteur: str) -> dict:
    """Corps de l'Operate ; l'acteur n'est transmis que s'il a la forme exigée par l'agent (sinon l'agent l'ignorerait)."""
    corps = {"command": commande, "args": args}
    if isinstance(acteur, str) and RE_ACTEUR.fullmatch(acteur):
        corps["acteur"] = acteur
    return corps


class Suivi:
    """Fin des opérations : audit du résultat et suite (Rejoindre après un renommage). Une instance, partagée par l'API et le
    canal (même processus, mêmes files)."""

    def __init__(self, stockage, files, audit: Callable[[str, dict], None], emettre: Optional[Callable[[str], str]] = None,
                 delai_rejoindre_s: float = DELAI_REJOINDRE_S, horloge: Callable[[], float] = time.monotonic) -> None:
        self.stockage, self.files, self.audit = stockage, files, audit
        self.emettre = emettre
        self.delai_rejoindre_s = delai_rejoindre_s
        self.delai_confirmer_s = DELAI_CONFIRMER_S
        self.horloge = horloge
        self.taches: set = set()
        self._orphelines: dict = {}   # Box.cle -> [instant de la dernière ligne, fins tues depuis] ; borné

    async def _auditer(self, evenement: str, champs: dict) -> None:
        try:
            await asyncio.to_thread(self.audit, evenement, champs)
        except Exception:
            log.exception("audit %s impossible", evenement)

    async def apres_fin(self, box: Box, op: dict) -> None:
        """Première fin d'un job (canal), ou fin d'une orpheline au moment de sa fusion avec la demande (API). N'audite que si l'action
        est connue (I1) : une box qui invente des jobs ne gonfle pas l'audit ; ses fins non rattachées font au plus une ligne de
        journal agrégée par box et par minute."""
        if op.get("action") is None:
            self._journaliser_orpheline(box)
            return
        await self._auditer("pilotage_action_resultat", {"box": box.nom, "cle": box.cle, "action": op.get("action"), "job": op.get("job"),
                                                         "rc": op.get("rc"), "resultat": op.get("resultat")})
        await self.suite(box, op)

    def _journaliser_orpheline(self, box: Box) -> None:
        maintenant = self.horloge()
        etat = self._orphelines.get(box.cle)
        if etat is not None and maintenant - etat[0] < JOURNAL_ORPHELINES_S:
            etat[1] += 1
            return
        tues = etat[1] if etat is not None else 0
        if etat is None and len(self._orphelines) >= 1024:
            self._orphelines.pop(next(iter(self._orphelines)))
        self._orphelines[box.cle] = [maintenant, 0]
        log.warning("%s : fin d'opération non rattachée à une demande (job inconnu du maître) ; %d autre(s) tue(s) depuis la ligne "
                    "précédente", box.cle, tues)

    async def suite(self, box: Box, op: dict) -> None:
        """Suite d'une opération terminée, une seule fois (réclamée en base) : Rejoindre après un renommage réussi ; confirmation
        après une bascule vers l'interface distante réussie (#3302)."""
        if op.get("etat") != "termine":
            return
        if nouveau_nom(box, op, {"rc": op.get("rc")}) is not None:
            suite = self._rejoindre
        elif op.get("action") == "interface-distante" and op.get("rc") == 0 and not isinstance(op.get("rc"), bool):
            suite = self._confirmer
        else:
            return
        if not await asyncio.to_thread(self.stockage.operation_reclamer_suite, op["id"]):
            return
        t = asyncio.create_task(suite(box, op))
        self.taches.add(t)
        t.add_done_callback(self.taches.discard)

    async def _rejoindre(self, box: Box, op: dict) -> None:
        nouveau = op["args"]["nom"]
        try:
            if self.emettre is None:
                raise ErreurRejoindre("émission du code non configurée")
            futur = await envoyer_rejoindre(self.files, box, op, {"rc": op.get("rc")}, emettre=self.emettre, audit=self.audit)
        except ErreurRejoindre as e:
            log.warning("rejoindre non envoyé à %s : %s", box.cle, e)
            await self._auditer("pilotage_rejoindre_echec", {"box": box.nom, "cle": box.cle, "nouveau": nouveau, "raison": str(e)})
            return
        except Exception:
            log.exception("rejoindre non envoyé à %s", box.cle)
            await self._auditer("pilotage_rejoindre_echec", {"box": box.nom, "cle": box.cle, "nouveau": nouveau, "raison": "erreur interne"})
            return
        if futur is None:
            return
        try:
            rep = await asyncio.wait_for(futur, self.delai_rejoindre_s)
        except asyncio.TimeoutError:
            etat, raison = "sans_reponse", ""
        else:
            corps = rep.get("body") if isinstance(rep.get("body"), dict) else {}
            if rep.get("type") == "OPERATE_RESP" and corps.get("etat") in ("accepte", "consentement", "refuse"):
                etat, raison = corps["etat"], corps.get("raison")
            else:
                etat, raison = "refuse", corps.get("err")
        champs = {"box": box.nom, "cle": box.cle, "nouveau": nouveau, "etat": etat}
        if raison:
            champs["raison"] = "".join(c for c in str(raison)[:200] if c.isprintable())
        await self._auditer("pilotage_rejoindre_resultat", champs)

    async def _confirmer(self, box: Box, op: dict) -> None:
        """#3302 : la box a basculé vers « distante » et attend la preuve que le maître la joint encore ; sans elle, son homme mort
        rend l'interface locale. La fin vient de remonter par le canal : la confirmation y redescend."""
        champs = {"box": box.nom, "cle": box.cle, "job": op.get("job")}
        try:
            # I1 : le job de la bascule confirmée ; la box refuse la confirmation d'une autre bascule
            futur = self.files.deposer(box.cle, {"type": "OPERATE", "body": {"command": COMMANDE_CONFIRMER, "args": {"job": op.get("job")}}})
        except Exception as e:  # noqa: BLE001 — file pleine : l'homme mort de la box rendra l'interface locale
            await self._auditer("pilotage_interface_confirmation", {**champs, "etat": "non_envoyee", "raison": e.__class__.__name__})
            return
        await self._auditer("pilotage_interface_confirmation", {**champs, "etat": "envoyee"})
        try:
            rep = await asyncio.wait_for(futur, self.delai_confirmer_s)
        except asyncio.TimeoutError:
            etat, raison = "sans_reponse", ""
        else:
            corps = rep.get("body") if isinstance(rep.get("body"), dict) else {}
            if rep.get("type") == "OPERATE_RESP" and corps.get("etat") in ("accepte", "consentement", "refuse"):
                etat, raison = corps["etat"], corps.get("raison")
            else:
                etat, raison = "refuse", corps.get("err")
        if raison:
            champs["raison"] = "".join(c for c in str(raison)[:200] if c.isprintable())
        await self._auditer("pilotage_interface_confirmation", {**champs, "etat": etat})

    async def attendre(self) -> None:
        """Attend la fin des suites en cours (tests, arrêt propre)."""
        while self.taches:
            await asyncio.gather(*list(self.taches), return_exceptions=True)

    async def arreter(self) -> None:
        for t in list(self.taches):
            t.cancel()
        await asyncio.gather(*list(self.taches), return_exceptions=True)
