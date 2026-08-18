#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox TUI splash — single-colour SECUBOX ROOT-green (Charte §05 ROOT).
# Previously alternated two greens per-letter ("S | EC | UB | OX") which was
# busy and rendered ugly under reduced-palette terminals (#fix-banner).
clear

# 256-colour codes approximating the SecuBox charter palette.
ROOT='\033[38;5;29m'   # ROOT teal-green  (~#0A5840 / Teal Root)
GOLD='\033[38;5;178m'  # Hermetic gold    (frame)
CYAN='\033[38;5;51m'   # Tagline accent
GRAY='\033[38;5;240m'  # Footer
RS='\033[0m'

cat << SPLASH

${GOLD}╔════════════════════════════════════════════════════════════════════════╗${RS}
${GOLD}║${RS}                                                                        ${GOLD}║${RS}
${GOLD}║${RS}   ${ROOT}███████╗███████╗ ██████╗██╗   ██╗██████╗  ██████╗ ██╗  ██╗${RS}          ${GOLD}║${RS}
${GOLD}║${RS}   ${ROOT}██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔═══██╗╚██╗██╔╝${RS}          ${GOLD}║${RS}
${GOLD}║${RS}   ${ROOT}███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║ ╚███╔╝${RS}           ${GOLD}║${RS}
${GOLD}║${RS}   ${ROOT}╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║ ██╔██╗${RS}           ${GOLD}║${RS}
${GOLD}║${RS}   ${ROOT}███████║███████╗╚██████╗╚██████╔╝██████╔╝╚██████╔╝██╔╝ ██╗${RS}          ${GOLD}║${RS}
${GOLD}║${RS}   ${ROOT}╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝${RS}          ${GOLD}║${RS}
${GOLD}║${RS}                                                                        ${GOLD}║${RS}
${GOLD}║${RS}              ${CYAN}Debian Cybersecurity Platform${RS}                             ${GOLD}║${RS}
${GOLD}║${RS}                    ${GRAY}CyberMind · cybermind.fr${RS}                            ${GOLD}║${RS}
${GOLD}║${RS}                                                                        ${GOLD}║${RS}
${GOLD}╚════════════════════════════════════════════════════════════════════════╝${RS}

SPLASH
