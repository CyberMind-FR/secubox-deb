#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — Plymouth Theme Asset Generator
#  Generates PNG assets for the SecuBox boot splash theme
#  Using 6-Module Color System
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

THEME_DIR="/usr/share/plymouth/themes/secubox"
OUTPUT_DIR="${1:-./plymouth-assets}"

# 6-Module Colors
BOOT_COLOR="#803018"
AUTH_COLOR="#C04E24"
ROOT_COLOR="#0A5840"
MIND_COLOR="#3D35A0"
MESH_COLOR="#104A88"
WALL_COLOR="#9A6010"

# Theme base colors
BG_DARK="#0B0F14"
SURFACE="#141A24"
TEXT_LIGHT="#E8ECF2"

mkdir -p "$OUTPUT_DIR"

echo "Generating SecuBox Plymouth theme assets..."

# Check for ImageMagick
if ! command -v convert &> /dev/null; then
    echo "Error: ImageMagick (convert) not found. Install with: apt install imagemagick"
    exit 1
fi

# 1. Logo (80x80 rounded square with S)
echo "  Creating logo.png..."
convert -size 80x80 xc:none \
    -fill "$ROOT_COLOR" -draw "roundrectangle 0,0 79,79 16,16" \
    -fill white -font DejaVu-Sans-Bold -pointsize 48 \
    -gravity center -annotate +0+0 "S" \
    "$OUTPUT_DIR/logo.png"

# 2. Progress box (300x12 rounded rectangle, dark)
echo "  Creating progress-box.png..."
convert -size 300x12 xc:none \
    -fill "$SURFACE" -draw "roundrectangle 0,0 299,11 6,6" \
    -stroke "$ROOT_COLOR" -strokewidth 1 -fill none \
    -draw "roundrectangle 0,0 299,11 6,6" \
    "$OUTPUT_DIR/progress-box.png"

# 3. Progress fill (298x10, gradient)
echo "  Creating progress-fill.png..."
convert -size 298x10 \
    gradient:"$ROOT_COLOR"-"$MESH_COLOR" \
    -gravity center -extent 298x10 \
    \( +clone -alpha extract -draw "roundrectangle 0,0 297,9 5,5" \) \
    -alpha off -compose CopyOpacity -composite \
    "$OUTPUT_DIR/progress-fill.png"

# 4. Module dots (12x12 circles for each module)
echo "  Creating module dots..."
for color in "$BOOT_COLOR" "$AUTH_COLOR" "$ROOT_COLOR" "$MIND_COLOR" "$MESH_COLOR" "$WALL_COLOR"; do
    name=$(echo "$color" | tr -d '#' | tr '[:upper:]' '[:lower:]')
    convert -size 12x12 xc:none \
        -fill "$color" -draw "circle 6,6 6,0" \
        "$OUTPUT_DIR/dot-$name.png"
done

# Generic dot (will be colored by script)
convert -size 12x12 xc:none \
    -fill white -draw "circle 6,6 6,0" \
    "$OUTPUT_DIR/dot.png"

# 5. Spinner frames (optional - 8 frames)
echo "  Creating spinner frames..."
for i in $(seq 0 7); do
    angle=$((i * 45))
    convert -size 48x48 xc:none \
        -stroke "$ROOT_COLOR" -strokewidth 4 -fill none \
        -draw "arc 4,4 44,44 $angle,$((angle + 90))" \
        "$OUTPUT_DIR/spinner-$i.png"
done

# 6. Background wallpaper (1920x1080)
echo "  Creating background.png..."
convert -size 1920x1080 \
    -define gradient:direction=south \
    gradient:"$BG_DARK"-"#020304" \
    "$OUTPUT_DIR/background.png"

# 7. SecuBox text image
echo "  Creating secubox-text.png..."
convert -size 400x60 xc:none \
    -fill "$TEXT_LIGHT" -font DejaVu-Sans-Bold -pointsize 48 \
    -gravity center -annotate +0+0 "SecuBox" \
    "$OUTPUT_DIR/secubox-text.png"

# 8. Subtitle text
echo "  Creating subtitle-text.png..."
convert -size 400x30 xc:none \
    -fill "#6B7A8C" -font DejaVu-Sans -pointsize 16 \
    -gravity center -annotate +0+0 "CyberMind Security Platform" \
    "$OUTPUT_DIR/subtitle-text.png"

echo ""
echo "Assets generated in: $OUTPUT_DIR"
echo ""
echo "To install:"
echo "  sudo cp $OUTPUT_DIR/*.png $THEME_DIR/"
echo "  sudo plymouth-set-default-theme secubox"
echo "  sudo update-initramfs -u"
