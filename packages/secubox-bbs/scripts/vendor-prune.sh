#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# SecuBox-Deb :: bbs — reduction de l'arbre vendor/
#
# POURQUOI CE SCRIPT EXISTE
#
# `go mod vendor` copie les paquets ENTIERS, tous fichiers compris. Or
# modernc.org/sqlite est du C transpile en Go, decline pour une quinzaine de
# couples systeme/architecture : 135 Mo dont nous n'utilisons que deux.
#
# Ce depot construit pour DEUX cibles et deux seulement :
#   - linux/arm64 : la board ;
#   - linux/amd64 : la machine de developpement et l'integration continue.
#
# Les fichiers des autres cibles sont supprimes. Ce n'est pas une bidouille :
# ils sont selectionnes par des marqueurs de compilation et ne seraient JAMAIS
# compiles ici. Les garder ne ferait que peser dans chaque clone, pour toujours.
#
# A relancer apres tout `go mod vendor`.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d vendor ] || { echo "vendor/ absent — lancez d'abord: go mod vendor" >&2; exit 1; }

avant=$(du -sm vendor | cut -f1)

find vendor -name '*.go' | while read -r f; do
    b=$(basename "$f" .go)
    # L'ORDRE COMPTE, et le premier jet de ce script s'y est trompe : tester
    # d'abord « se termine par _arm64 » laissait passer
    # sqlite_freebsd_arm64.go — 8 Mo de FreeBSD gardes parce que le nom finit
    # par une architecture que nous visons. Le SYSTEME se teste en premier.
    case "$b" in
        *_windows*|*_darwin*|*_freebsd*|*_netbsd*|*_openbsd*|*_dragonfly*|\
        *_solaris*|*_illumos*|*_aix*|*_plan9*|*_js*|*_wasip1*|*_ios*|*_android*)
            rm -f "$f"; continue ;;
    esac
    case "$b" in
        *_linux_amd64|*_linux_arm64|*_amd64|*_arm64) continue ;;
    esac
    case "$b" in
        *_386|*_arm|*_ppc64|*_ppc64le|*_mips|*_mipsle|*_mips64|*_mips64le|\
        *_s390x|*_riscv64|*_loong64|*_wasm|*_sparc64)
            rm -f "$f" ;;
    esac
done

find vendor -type d -empty -delete 2>/dev/null || true

apres=$(du -sm vendor | cut -f1)
echo "vendor/ : ${avant} Mo -> ${apres} Mo"

# LA VERIFICATION FAIT PARTIE DU SCRIPT. Un elagage qui casse la compilation
# doit se voir ici, pas trois commits plus tard sur la board.
echo "verification arm64…"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off \
    go build -trimpath -o /dev/null ./cmd/... || { echo "ELAGAGE INVALIDE (arm64)" >&2; exit 1; }
echo "verification amd64 + tests…"
GOFLAGS=-mod=vendor GOPROXY=off go test ./... >/dev/null || {
    echo "ELAGAGE INVALIDE (tests amd64)" >&2; exit 1; }
echo "les deux cibles compilent, les tests passent."
