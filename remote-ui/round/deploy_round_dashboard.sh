#!/usr/bin/env bash
# ============================================================
#  deploy_round_dashboard.sh
#  Déploie le dashboard HyperPixel Round sur le RPi Zero W
#
#  Usage : ./deploy_round_dashboard.sh [OPTIONS]
#    -h HOST     IP ou hostname du Zero W  (défaut: rpi-zero-round.local)
#    -u USER     Utilisateur SSH           (défaut: pi)
#    -p PORT     Port SSH                  (défaut: 22)
#    --sim       Garder mode simulation (ne pas passer en mode API réel)
#    --help      Aide
# ============================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
step()  { echo -e "\n${BOLD}━━ $* ${NC}"; }

HOST="rpi-zero-round.local"
USER="pi"
PORT=22
SIMULATE=true
DASHBOARD_SRC="$(dirname "$0")/secubox_round_dashboard.html"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h) HOST="$2"; shift 2 ;;
    -u) USER="$2"; shift 2 ;;
    -p) PORT="$2"; shift 2 ;;
    --sim) SIMULATE=true; shift ;;
    --no-sim) SIMULATE=false; shift ;;
    --help) grep '^#' "$0" | head -20 | sed 's/^# \{0,2\}//'; exit 0 ;;
    *) error "Option inconnue: $1" ;;
  esac
done

SSH="ssh -p $PORT -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new ${USER}@${HOST}"
SCP="scp -P $PORT -o ConnectTimeout=10"

step "Test de connexion SSH vers $HOST"
$SSH "echo 'SSH OK'" || error "Impossible de joindre $HOST"
ok "Connecté à $HOST"

step "Vérification / installation nginx + chromium"
$SSH "bash -s" << 'REMOTE'
set -e
pkgs=()
command -v nginx     &>/dev/null || pkgs+=(nginx)
command -v chromium  &>/dev/null || command -v chromium-browser &>/dev/null || pkgs+=(chromium-browser)
if [[ ${#pkgs[@]} -gt 0 ]]; then
  echo "Installation: ${pkgs[*]}"
  sudo apt-get update -qq
  sudo apt-get install -y -qq "${pkgs[@]}"
fi
echo "nginx et chromium présents"
REMOTE
ok "Dépendances OK"

step "Déploiement du dashboard HTML"

# Patcher le mode simulation si demandé
TMP_HTML="/tmp/dashboard_deploy_$$.html"
cp "$DASHBOARD_SRC" "$TMP_HTML"

if ! $SIMULATE; then
  sed -i "s/SIMULATE: true/SIMULATE: false/" "$TMP_HTML"
  info "Mode API réelle activé dans le HTML"
else
  info "Mode simulation conservé"
fi

$SSH "sudo mkdir -p /var/www/secubox-round && sudo chown $USER:$USER /var/www/secubox-round"
$SCP "$TMP_HTML" "${USER}@${HOST}:/var/www/secubox-round/index.html"
rm "$TMP_HTML"
ok "index.html déployé dans /var/www/secubox-round/"

step "Configuration nginx"
$SSH "bash -s" << 'NGINX'
cat | sudo tee /etc/nginx/sites-available/secubox-round > /dev/null << 'NGINXCFG'
server {
    listen 8080 default_server;
    root /var/www/secubox-round;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header X-Frame-Options SAMEORIGIN;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 5s;
        proxy_connect_timeout 3s;
    }
}
NGINXCFG
sudo ln -sf /etc/nginx/sites-available/secubox-round /etc/nginx/sites-enabled/secubox-round
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx
echo "nginx OK sur port 8080"
NGINX
ok "nginx configuré (port 8080, proxy /api/ → localhost:8000)"

step "Configuration service kiosk systemd"
$SSH "bash -s" << KIOSK_SVC
cat | sudo tee /etc/systemd/system/kiosk.service > /dev/null << 'SVCEOF'
[Unit]
Description=SecuBox Round Dashboard Kiosk
After=network.target graphical.target nginx.service

[Service]
Type=simple
User=$USER
Environment=DISPLAY=:0
Environment=XAUTHORITY=/home/$USER/.Xauthority
Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
ExecStartPre=/bin/sleep 8
ExecStart=/usr/bin/chromium-browser \
  --kiosk \
  --window-size=480,480 \
  --window-position=0,0 \
  --start-fullscreen \
  --no-first-run \
  --disable-infobars \
  --disable-session-crashed-bubble \
  --disable-restore-session-state \
  --disable-translate \
  --disable-features=TranslateUI \
  --check-for-update-interval=31536000 \
  --noerrdialogs \
  --hide-scrollbars \
  --app=http://localhost:8080
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=graphical.target
SVCEOF
sudo systemctl daemon-reload
sudo systemctl enable kiosk.service
echo "Service kiosk activé"
KIOSK_SVC
ok "kiosk.service activé au démarrage"

step "Configuration autologin X11 (lightdm)"
$SSH "bash -s" << AUTOLOGIN
if command -v lightdm &>/dev/null; then
  sudo mkdir -p /etc/lightdm/lightdm.conf.d
  cat | sudo tee /etc/lightdm/lightdm.conf.d/autologin.conf > /dev/null << 'LGEOF'
[Seat:*]
autologin-user=pi
autologin-user-timeout=0
LGEOF
  echo "lightdm autologin configuré"
else
  echo "lightdm absent, autologin via raspi-config requis"
fi
AUTOLOGIN

step "Désactivation économiseur d'écran / DPMS"
$SSH "bash -s" << NODPMS
XINITRC="/home/$USER/.xinitrc"
grep -q "xset s off" \$XINITRC 2>/dev/null || cat >> \$XINITRC << 'XEOF'
xset s off
xset s noblank
xset -dpms
XEOF
echo "DPMS désactivé"
NODPMS

ok "Configuration écran terminée"

step "Test final — accès dashboard"
HTTP_CODE=$($SSH "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080" || echo "000")
if [[ "$HTTP_CODE" == "200" ]]; then
  ok "Dashboard accessible → http://${HOST}:8080"
else
  warn "Dashboard pas encore accessible (code: $HTTP_CODE) — attendre le reboot"
fi

step "Résumé"
echo ""
echo -e "  ${GREEN}✓${NC} Dashboard HTML déployé"
echo -e "  ${GREEN}✓${NC} nginx sur port 8080 (proxy /api/ → :8000)"
echo -e "  ${GREEN}✓${NC} kiosk.service systemd activé"
echo -e "  ${GREEN}✓${NC} Autologin X11"
echo -e "  ${GREEN}✓${NC} DPMS/screensaver désactivé"
echo ""
echo -e "  ${BOLD}Pour démarrer le kiosk :${NC}"
echo -e "    ${CYAN}ssh ${USER}@${HOST} 'sudo reboot'${NC}"
echo ""
echo -e "  ${BOLD}Pour passer en mode API réelle :${NC}"
echo -e "    ${CYAN}./deploy_round_dashboard.sh -h $HOST --no-sim${NC}"
echo ""
echo -e "  ${BOLD}API SecuBox endpoint métriques attendu :${NC}"
echo -e "    GET  http://${HOST}:8000/api/v1/system/metrics"
echo -e "    POST http://${HOST}:8000/api/v1/auth/token"
echo ""
