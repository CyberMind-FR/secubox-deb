#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# scripts/stage-gpg-bootstrap.sh
# Initialize the SecuBox package signing key in ~/.gnupg/secubox/.
# Writes:
#   ~/.gnupg/secubox/                  - persistent gnupg home (chmod 700)
#   $OUT_DIR/secubox-keyring.gpg       - public key, ASCII-armored
#   $OUT_DIR/secubox-keyring.gpg.bin   - public key, binary
#   $OUT_DIR/FINGERPRINT.txt           - long fingerprint (no spaces)
#
# Idempotent: skips key creation if a key for packages@secubox.in already exists.

set -euo pipefail

OUT_DIR="${1:-output/repo}"
KEY_EMAIL="packages@secubox.in"
export GPG_HOME="${HOME}/.gnupg/secubox"
export EXPORT_DIR="$OUT_DIR"

mkdir -p "$OUT_DIR" "$GPG_HOME"
chmod 700 "$GPG_HOME"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SCRIPT_DIR")"

bash "$REPO/repo/scripts/generate-gpg-key.sh"

# The underlying script exits early (without exporting) when the key already
# exists.  Always export here so the wrapper is idempotent end-to-end.
gpg --homedir "$GPG_HOME" --armor --export "$KEY_EMAIL" \
  > "$OUT_DIR/secubox-keyring.gpg"
gpg --homedir "$GPG_HOME" --export "$KEY_EMAIL" \
  > "$OUT_DIR/secubox-keyring.gpg.bin"

# Extract long fingerprint (no spaces) — used in reprepro conf/distributions SignWith.
gpg --homedir "$GPG_HOME" \
    --list-keys --with-colons "$KEY_EMAIL" \
  | awk -F: '/^fpr:/ {print $10; exit}' \
  > "$OUT_DIR/FINGERPRINT.txt"

if [[ ! -s "$OUT_DIR/FINGERPRINT.txt" ]]; then
  echo "ERROR: failed to extract fingerprint" >&2
  exit 1
fi

echo "GPG ready. Fingerprint: $(cat "$OUT_DIR/FINGERPRINT.txt")"
echo "Public key (armored): $OUT_DIR/secubox-keyring.gpg"
echo "Public key (binary):  $OUT_DIR/secubox-keyring.gpg.bin"
