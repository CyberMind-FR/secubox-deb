#!/bin/bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# SecuBox-Deb :: secubox-aggregator-watchdog
#
# Auto-heal the in-process aggregator — the hub/auth/menu single point of
# failure. Under a host load spike its shared event loop can wedge and its
# socket stops answering, taking down the navbar, login and service status
# board-wide (incident 2026-06-24). Probe the socket; if /api/v1/hub/public/menu
# stops answering for N consecutive checks, restart the service. Idempotent,
# safe to run on a timer.
set -uo pipefail
readonly MODULE="secubox-aggregator-watchdog"
readonly VERSION="1.0"

SOCK="/run/secubox/aggregator.sock"
# State lives in /run (root-owned), NOT the shared sticky /run/secubox: that dir
# is 1777 and a stale secubox-owned file there can't be overwritten by this
# (CSPN-hardened, CAP_DAC_OVERRIDE-less) root — which would silently freeze the
# streak counter and stop the watchdog ever triggering.
STATE="/run/secubox-aggregator-watchdog.fails"
FAIL_THRESHOLD="${SECUBOX_AGG_WD_THRESHOLD:-2}"
TIMEOUT="${SECUBOX_AGG_WD_TIMEOUT:-12}"

# No socket yet (service still starting / not migrated) → nothing to heal.
[ -S "$SOCK" ] || exit 0

# ON SONDE L AGREGATEUR, PAS UN MODULE.
#
# La sonde visait /api/v1/hub/public/menu — un point d entree qui traverse le
# hub ET son cache d etat. Quand le hub etait lent, la sonde echouait et c est
# l AGREGATEUR qui etait redemarre : on tuait le porteur pour la faute d un
# passager. Six redemarrages en une heure le 2026-08-17.
#
# `/health` ne depend que de l agregateur lui-meme : il repond des qu il est
# capable de servir, et pas avant.
#
# `|| echo 000` retire : curl ecrit deja 000 en cas d echec, et le repli en
# ajoutait un second — d ou les « code=000000 » du journal, qui rendaient toute
# comparaison numerique impossible.
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" \
        --unix-socket "$SOCK" http://localhost/health 2>/dev/null)
[ -n "$code" ] || code=000

if [ "$code" = "200" ]; then
    echo 0 > "$STATE" 2>/dev/null || true
    exit 0
fi

n=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STATE" 2>/dev/null || true
logger -t "$MODULE" "aggregator probe failed (code=$code, streak=$n/$FAIL_THRESHOLD)"

# Startup grace: the aggregator mounts ~110 modules in-process on cold start
# (several minutes). RuntimeDirectoryPreserve keeps the socket FILE across
# restarts, so a still-starting aggregator looks "present but unresponsive" to
# the probe. Do NOT auto-heal while it is within the grace window, or we kill it
# before it can finish binding (self-inflicted restart loop).
# 900 s et non 480 : le montage des ~110 modules a pris 360 s a vide le
# 2026-08-17, et davantage sous charge. Une grace trop courte tue l agregateur
# juste avant qu il finisse, et le redemarrage repart de zero — la boucle se
# nourrit d elle-meme.
GRACE="${SECUBOX_AGG_WD_GRACE:-900}"
_mainpid=$(systemctl show secubox-aggregator -p MainPID --value 2>/dev/null || echo 0)
if [ -n "$_mainpid" ] && [ "$_mainpid" != 0 ]; then
    _up=$(ps -o etimes= -p "$_mainpid" 2>/dev/null | tr -d " ")
    if [ -n "$_up" ] && [ "$_up" -lt "$GRACE" ]; then
        logger -t "$MODULE" "aggregator up ${_up}s (<${GRACE}s grace) — still starting, not restarting"
        exit 0
    fi
    # AU-DELA DE LA GRACE, ON REGARDE S IL AVANCE.
    #
    # Un processus qui consomme du CPU est en train de faire quelque chose —
    # importer un module, resoudre une dependance. Le tuer parce qu une horloge
    # arbitraire a sonne, c est perdre le travail deja fait et recommencer.
    # On ne redemarre que ce qui est reellement FIGE.
    _c1=$(awk "{print \$14+\$15}" "/proc/$_mainpid/stat" 2>/dev/null || echo 0)
    sleep 5
    _c2=$(awk "{print \$14+\$15}" "/proc/$_mainpid/stat" 2>/dev/null || echo 0)
    if [ "${_c2:-0}" -gt "${_c1:-0}" ] 2>/dev/null; then
        logger -t "$MODULE" "aggregator consomme encore du CPU (${_c1}->${_c2}) — il avance, pas de redemarrage"
        exit 0
    fi
fi

if [ "$n" -ge "$FAIL_THRESHOLD" ]; then
    logger -t "$MODULE" "restarting secubox-aggregator (auto-heal)"
    systemctl restart secubox-aggregator.service
    echo 0 > "$STATE" 2>/dev/null || true
fi
exit 0
