# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Construit les deux applications du service Pilotage (#3126) : l'administration (/run/secubox/pilotage.sock) et le canal des box
(/run/secubox/pilotage-canal.sock). Les files (`Files`) sont en mémoire : les deux applications DOIVENT tourner dans le même processus.
La boucle de relève démarre avec la première des deux applications lancée (démarrage idempotent) et s'arrête avec elle."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from api.canal import creer_app_canal
from api.main import creer_app_admin
from pilotage import audit as A
from pilotage.files import Files
from pilotage.identite import box_par_adresse
from pilotage.inventaire import Inventaire
from pilotage.stockage import DOSSIER_DEFAUT, StockageSqlite


def construire() -> "tuple[FastAPI, FastAPI]":
    stockage = StockageSqlite(Path(os.environ.get("SECUBOX_PILOTAGE_DOSSIER", DOSSIER_DEFAUT)))
    audit = A.journal(Path(os.environ.get("SECUBOX_PILOTAGE_AUDIT", A.AUDIT_DEFAUT)))
    files = Files()
    inventaire = Inventaire(files, stockage)
    admin = creer_app_admin(stockage, files, inventaire, audit)
    canal = creer_app_canal(files, box_par_adresse, stockage, audit)

    @asynccontextmanager
    async def vie_canal(app):
        inventaire.demarrer()
        try:
            yield
        finally:
            await inventaire.arreter()

    canal.router.lifespan_context = vie_canal
    return admin, canal
