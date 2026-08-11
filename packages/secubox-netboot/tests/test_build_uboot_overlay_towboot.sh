#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
# fake tow-boot artifact dir
mkdir -p "$tmp/tb"; head -c 4096 /dev/zero > "$tmp/tb/Tow-Boot.spi.bin"
# run in --tow-boot mode for mochabin into a staging dir
bash "$HERE/scripts/build-uboot-overlay.sh" --board mochabin \
     --tow-boot "$tmp/tb" --key-dir "$tmp/keys" --out "$tmp/out"
test -s "$tmp/out/sbx-uboot.fit"  || { echo "FAIL: no sbx-uboot.fit"; exit 1; }
test -s "$tmp/out/sbx-boot.scr"   || { echo "FAIL: no sbx-boot.scr";  exit 1; }
mkimage -l "$tmp/out/sbx-uboot.fit" | grep -qi "Sign algo" \
     || { echo "FAIL: FIT not signed"; exit 1; }
echo "PASS"
