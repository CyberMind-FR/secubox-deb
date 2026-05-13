#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# /home/secubox/.xinitrc — entry for xinit (runs after secubox-kiosk-x.service starts X)
exec openbox --startup "/etc/openbox/autostart"
