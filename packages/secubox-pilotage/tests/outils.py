# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

"""Aides communes aux tests du stockage, de l'inventaire et de l'API d'administration."""
from pilotage.identite import Box

P = "Device."
GK5 = Box("gk5", "10.10.0.5", "maillage", None, None)
GK5_AUTOLOAD = Box("gk5", "10.64.0.9", "autoload", "acme", "actif")
GK2 = Box("gk2", "10.10.0.2", "maillage", None, None)


class Horloge:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def avance(self, s):
        self.t += s


def releve_gk5(swap_total=1000, swap_used=660, failed=0, mains=None, dispo_kio=524288, cpu=12, interface=None):
    params = {
        P + "DeviceInfo.MemoryStatus.X_SECUBOX_Available": dispo_kio,
        P + "DeviceInfo.MemoryStatus.X_SECUBOX_SwapTotal": swap_total,
        P + "DeviceInfo.MemoryStatus.X_SECUBOX_SwapUsed": swap_used,
        P + "DeviceInfo.ProcessStatus.CPUUsage": cpu,
        P + "X_SECUBOX_Services.FailedNumberOfEntries": failed,
        P + "X_SECUBOX_Services.1.Name": "secubox-hub.service",
        P + "X_SECUBOX_Services.1.NRestarts": 0,
    }
    if mains is not None:
        params[P + "X_SECUBOX_Pilotage.MainsLiees"] = mains
    if interface is not None:
        params[P + "X_SECUBOX_Pilotage.Interface"] = interface
    return {"results": [{"path": P, "params": params}]}
