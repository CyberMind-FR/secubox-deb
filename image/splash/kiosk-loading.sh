#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox Kiosk Loading Splash
# Shows animated loading progress

# Colors
G='\033[38;5;40m'   # Green
GO='\033[38;5;178m' # Gold
CY='\033[38;5;51m'  # Cyan
GR='\033[38;5;240m' # Gray
RS='\033[0m'

spinner="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
progress_bar() {
    local width=40
    local percent=$1
    local filled=$((percent * width / 100))
    local empty=$((width - filled))
    printf "\r  ${GO}[${G}"
    printf "%0.s█" $(seq 1 $filled)
    printf "%0.s░" $(seq 1 $empty)
    printf "${GO}]${RS} ${percent}%%"
}

clear
cat << SPLASH

${GO}╔══════════════════════════════════════════════════════════════╗${RS}
${GO}║${RS}                                                              ${GO}║${RS}
${GO}║${RS}        ${G}SecuBox${RS} ${CY}Kiosk Mode${RS}                                   ${GO}║${RS}
${GO}║${RS}                                                              ${GO}║${RS}
${GO}╚══════════════════════════════════════════════════════════════╝${RS}

SPLASH

stages=(
    "Initializing X11 display..."
    "Configuring network interface..."
    "Starting nginx web server..."
    "Loading SecuBox services..."
    "Launching browser..."
)

for i in "${!stages[@]}"; do
    echo -e "\n  ${CY}${spinner:i%10:1}${RS} ${stages[$i]}"
    progress_bar $((20 + i * 20))
    sleep 0.5
done

echo -e "\n\n  ${G}✓${RS} ${GO}Kiosk ready${RS}\n"
