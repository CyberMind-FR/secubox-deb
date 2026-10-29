# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Construit les deux applications du service Pilotage (#3126) : l'administration (/run/secubox/pilotage.sock) et le canal des box
(/run/secubox/pilotage-canal.sock). Les files (`Files`) sont en mémoire : les deux applications DOIVENT tourner dans le même processus.
La boucle de relève démarre avec le premier lifespan et ne s'arrête que quand les DEUX applications se sont arrêtées : les servir avec lifespan=on."""
import os
import time
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


def assembler(stockage, files, inventaire, audit, identifier, horloge=time.time) -> "tuple[FastAPI, FastAPI]":
    """Les deux applications sur les mêmes files, le même stockage et la même boucle de relève (cycle de vie partagé, par compteur)."""
    admin = creer_app_admin(stockage, files, inventaire, audit, horloge=horloge)
    canal = creer_app_canal(files, identifier, stockage, audit)

    @asynccontextmanager
    async def vie_canal(app):
        async with inventaire.utiliser():
            yield

    canal.router.lifespan_context = vie_canal
    return admin, canal


def construire() -> "tuple[FastAPI, FastAPI]":
    stockage = StockageSqlite(Path(os.environ.get("SECUBOX_PILOTAGE_DOSSIER", DOSSIER_DEFAUT)))
    audit = A.journal(Path(os.environ.get("SECUBOX_PILOTAGE_AUDIT", A.AUDIT_DEFAUT)))
    files = Files()
    return assembler(stockage, files, Inventaire(files, stockage), audit, box_par_adresse)
