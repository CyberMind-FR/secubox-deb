#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  fix-emoji-fonts.sh — Configure fontconfig for emoji icons
#  Run this on the SecuBox VM to fix sidebar emoji icons
#  CyberMind — https://cybermind.fr
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

echo "[fix] Configuring emoji font support..."

# Install Noto Color Emoji if not present
if ! dpkg -l fonts-noto-color-emoji 2>/dev/null | grep -q "^ii"; then
    echo "[fix] Installing fonts-noto-color-emoji..."
    apt-get update -qq
    apt-get install -y -qq fonts-noto-color-emoji
fi

# Create fontconfig for emoji
mkdir -p /etc/fonts/conf.d
cat > /etc/fonts/conf.d/99-noto-emoji.conf <<'FONTCONF'
<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig>
  <!-- Use Noto Color Emoji for emoji characters -->
  <match target="pattern">
    <test name="family"><string>emoji</string></test>
    <edit name="family" mode="prepend" binding="strong">
      <string>Noto Color Emoji</string>
    </edit>
  </match>

  <!-- Add Noto Color Emoji as fallback for all fonts -->
  <match target="pattern">
    <edit name="family" mode="append">
      <string>Noto Color Emoji</string>
    </edit>
  </match>

  <!-- Prefer color emoji over text emoji -->
  <selectfont>
    <acceptfont>
      <pattern>
        <patelt name="family"><string>Noto Color Emoji</string></patelt>
      </pattern>
    </acceptfont>
  </selectfont>
</fontconfig>
FONTCONF

# Rebuild font cache
echo "[fix] Rebuilding font cache..."
fc-cache -f -v 2>/dev/null || fc-cache -f

echo "[fix] Done! Restart Chromium to see emoji icons."
echo "[fix] Run: pkill chromium; /usr/local/bin/start-kiosk &"
