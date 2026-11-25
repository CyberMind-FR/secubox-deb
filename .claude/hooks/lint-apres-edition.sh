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
#   tout fichier connu de scripts/license-headers.py → en-tête CMSD-1.0 posé s'il manque (#3950)
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

# #3950 : en-tête CMSD-1.0 posé tout de suite sur un fichier neuf (l'échec « License Headers » de la CI vient de là). L'outil ne
# touche que les extensions qu'il connaît, les fichiers suivis ou non ignorés, et jamais un en-tête déjà présent (ni tiers).
entete=""
depot=$(git -C "$(dirname "$chemin")" rev-parse --show-toplevel 2>/dev/null || true)
if [ -n "$depot" ] && [ -f "$depot/scripts/license-headers.py" ] && command -v python3 >/dev/null 2>&1 \
   && ! git -C "$depot" check-ignore -q -- "$chemin" 2>/dev/null; then
    manque=$(cd "$depot" 2>/dev/null; python3 scripts/license-headers.py --list -- "$chemin" 2>/dev/null) || manque=""
    if [ -n "$manque" ] && (cd "$depot" && python3 scripts/license-headers.py --fix -- "$chemin" >/dev/null 2>&1); then
        entete="En-tête CMSD-1.0 ajouté en tête du fichier (le relire avant un nouvel Edit)."
    fi
fi

rendre() {  # $1 outil, $2 texte
    jq -n --arg o "$1" --arg f "$chemin" --arg t "$2" '{
        hookSpecificOutput: {
            hookEventName: "PostToolUse",
            additionalContext: ("Lint après édition — " + $o + " sur " + $f + " :\n" + $t)
        }
    }'
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
    *) outil="licence" ;;
esac

if [ -z "$sortie" ]; then
    [ -z "$entete" ] || rendre licence "$entete"
    exit 0
fi
[ -z "$entete" ] || sortie="$entete
$sortie"

# 40 lignes au plus : le contexte de la session n'est pas une poubelle.
extrait=$(printf '%s\n' "$sortie" | head -n 40)
total=$(printf '%s\n' "$sortie" | wc -l | tr -d ' ')
suite=""
[ "$total" -le 40 ] || suite="
… ($((total - 40)) ligne(s) de plus)"

rendre "$outil" "$extrait$suite"
exit 0
