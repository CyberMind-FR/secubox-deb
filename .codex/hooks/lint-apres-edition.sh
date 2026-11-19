#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: hook PostToolUse — lint du SEUL fichier touché (#1863)
#
# Branché sur Edit|Write|MultiEdit (.claude/settings.json). Lit le JSON de
# l'événement sur l'entrée standard, ne regarde que `tool_input.file_path` :
#   *.py                          → ruff check (sans correction)
#   *.sh                          → shellcheck
#   debian/{pre,post}{inst,rm},
#   debian/*.{pre,post}{inst,rm}  → sh -n
# Rapide (un fichier, un outil). Un constat est renvoyé à la session par
# `additionalContext` ; code de sortie 0 dans tous les cas : un lint ne bloque
# jamais une édition, et un outil absent n'est pas une erreur.
set -eu

command -v jq >/dev/null 2>&1 || exit 0

entree=$(cat)
chemin=$(printf '%s' "$entree" | jq -r '.tool_input.file_path // empty' 2>/dev/null || true)
[ -n "$chemin" ] || exit 0
[ -f "$chemin" ] || exit 0

racine=${CLAUDE_PROJECT_DIR:-$(pwd)}

# ruff : PATH, puis le .venv du projet, puis celui du dépôt principal (un worktree n'a pas le sien).
trouve_ruff() {
    if command -v ruff >/dev/null 2>&1; then command -v ruff; return 0; fi
    if [ -x "$racine/.venv/bin/ruff" ]; then printf '%s\n' "$racine/.venv/bin/ruff"; return 0; fi
    commun=$(git -C "$racine" rev-parse --git-common-dir 2>/dev/null || true)
    if [ -n "$commun" ]; then
        cand=$(cd "$racine" && cd "$commun/.." 2>/dev/null && pwd)/.venv/bin/ruff
        if [ -x "$cand" ]; then printf '%s\n' "$cand"; return 0; fi
    fi
    return 1
}

sortie=""
outil=""
case "$chemin" in
    */debian/postinst|*/debian/preinst|*/debian/prerm|*/debian/postrm|\
    */debian/*.postinst|*/debian/*.preinst|*/debian/*.prerm|*/debian/*.postrm)
        outil="sh -n"
        sortie=$(sh -n "$chemin" 2>&1 || true)
        ;;
    *.py)
        outil="ruff"
        if ruff_bin=$(trouve_ruff); then
            sortie=$("$ruff_bin" check --no-fix --output-format=concise -- "$chemin" 2>&1 || true)
            # « All checks passed! » n'est pas un constat.
            case "$sortie" in "All checks passed"*) sortie="" ;; esac
        fi
        ;;
    *.sh)
        outil="shellcheck"
        if command -v shellcheck >/dev/null 2>&1; then
            sortie=$(shellcheck -f gcc "$chemin" 2>&1 || true)
        fi
        ;;
    *) exit 0 ;;
esac

[ -n "$sortie" ] || exit 0

# 40 lignes au plus : le contexte de la session n'est pas une poubelle.
extrait=$(printf '%s\n' "$sortie" | head -n 40)
total=$(printf '%s\n' "$sortie" | wc -l | tr -d ' ')
suite=""
[ "$total" -le 40 ] || suite="
… ($((total - 40)) ligne(s) de plus)"

jq -n --arg o "$outil" --arg f "$chemin" --arg t "$extrait$suite" '{
    hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: ("Lint après édition — " + $o + " sur " + $f + " :\n" + $t)
    }
}'
exit 0
