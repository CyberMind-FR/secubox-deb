#!/bin/sh
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
#
# Écrit sur la sortie standard le version.json de l'APK donné : version, version_code, empreinte et taille réelles.
# Usage : version-json.sh <apk> <version> <version_code>
set -eu
apk="${1:?apk}"; version="${2:?version}"; code="${3:?version_code}"
[ -f "$apk" ] || { echo "version-json : APK introuvable ($apk)" >&2; exit 1; }
sha=$(sha256sum "$apk" | cut -d' ' -f1)
taille=$(stat -c %s "$apk")
printf '{"version": "%s", "version_code": %s, "sha256": "%s", "taille": %s, "fichier": "secubox-companion.apk"}\n' \
  "$version" "$code" "$sha" "$taille"
