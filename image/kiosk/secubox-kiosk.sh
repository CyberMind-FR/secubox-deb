#!/bin/bash
# SecuBox-DEB :: Kiosk X Session Startup Script
# Launches Chromium in fullscreen kiosk mode pointing to localhost
# CyberMind - https://cybermind.fr

# Kiosk URL - Use HTTPS localhost (chromium ignores cert errors)
KIOSK_URL="${KIOSK_URL:-https://localhost/}"

# Disable screen blanking and power management
xset s off
xset s noblank
xset -dpms

# Set background to black
xsetroot -solid "#0a0a0f"

# Display loading splash if available
if [[ -x /usr/share/secubox/splash/kiosk-loading.sh ]]; then
    /usr/share/secubox/splash/kiosk-loading.sh &
    SPLASH_PID=$!
fi

# Wait for nginx/web server to be ready
max_wait=60
waited=0
while ! curl -sk --connect-timeout 1 "$KIOSK_URL" > /dev/null 2>&1; do
    sleep 1
    waited=$((waited + 1))
    if [[ $waited -ge $max_wait ]]; then
        echo "Warning: Web server not responding after ${max_wait}s" | logger -t secubox-kiosk
        break
    fi
done

# Kill splash if running
[[ -n "$SPLASH_PID" ]] && kill "$SPLASH_PID" 2>/dev/null

# Launch Chromium in kiosk mode
exec chromium \
    --kiosk \
    --no-sandbox \
    --disable-infobars \
    --disable-session-crashed-bubble \
    --disable-restore-session-state \
    --disable-translate \
    --disable-features=TranslateUI \
    --noerrdialogs \
    --check-for-update-interval=31536000 \
    --disable-component-update \
    --disable-background-networking \
    --disable-sync \
    --disable-default-apps \
    --ignore-certificate-errors \
    --ignore-ssl-errors \
    --ignore-certificate-errors-spki-list \
    --ignore-urlfetcher-cert-requests \
    --allow-insecure-localhost \
    --start-fullscreen \
    --window-position=0,0 \
    --user-data-dir=/tmp/chromium-kiosk \
    "$KIOSK_URL"
