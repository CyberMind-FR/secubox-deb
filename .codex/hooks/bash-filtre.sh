#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: hook PreToolUse (Bash) des subagents — liste blanche (#1863)
#
# Usage : bash-filtre.sh lecture|lint
#   lecture : git diff|log|show|status|blame|rev-parse|ls-files|merge-base,
#             grep, rg, ls, wc, head, tail, stat, file, diff
#   lint    : lecture + ruff (check, format — `--fix` compris : c'est le métier du
#             correcteur-lint), shellcheck, sh -n, bash -n, pytest
# Refuse (code 2, message sur stderr, renvoyé à l'agent) toute autre commande, et
# tout enchaînement ou redirection : ; & | > < ` $( et saut de ligne.
set -eu

mode=${1:-lecture}
command -v jq >/dev/null 2>&1 || { echo "bash-filtre : jq absent, Bash refusé" >&2; exit 2; }

commande=$(jq -r '.tool_input.command // empty' 2>/dev/null || true)
[ -n "$commande" ] || exit 0

refuse() {
    echo "Refusé (mode $mode) : $1. Commande : $commande" >&2
    exit 2
}

# Pas d'enchaînement, de redirection ni de substitution.
# shellcheck disable=SC2016  # les motifs `$(` et backquote sont volontairement littéraux
case "$commande" in
    *';'*|*'&'*|*'|'*|*'>'*|*'<'*|*'`'*|*'$('*) refuse "enchaînement, redirection ou substitution interdits" ;;
esac
case "$commande" in
    *'
'*) refuse "plusieurs lignes interdites" ;;
esac

# shellcheck disable=SC2086  # découpage volontaire en mots
set -- $commande
premier=$1
second=${2:-}
troisieme=${3:-}

lecture_ok() {
    case "$premier" in
        grep|rg|ls|wc|head|tail|stat|file|diff) return 0 ;;
        git)
            case "$second" in
                diff|log|show|status|blame|rev-parse|ls-files|merge-base) return 0 ;;
            esac ;;
    esac
    return 1
}

lint_ok() {
    case "$premier" in
        ruff|.venv/bin/ruff|./.venv/bin/ruff)
            [ "$second" = "check" ] || [ "$second" = "format" ] ;;
        shellcheck|pytest|.venv/bin/pytest) return 0 ;;
        sh|bash) [ "$second" = "-n" ] ;;
        python3|python|.venv/bin/python) [ "$second" = "-m" ] && [ "$troisieme" = "pytest" ] ;;
        *) return 1 ;;
    esac
}

case "$mode" in
    lecture) lecture_ok || refuse "commande hors liste blanche de lecture" ;;
    lint)    lecture_ok || lint_ok || refuse "commande hors liste blanche de lint" ;;
    *)       refuse "mode inconnu" ;;
esac
exit 0
