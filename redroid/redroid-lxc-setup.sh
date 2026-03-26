#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════╗
# ║   ReDroid LXC Setup Wizard — CyberMind SecuBox-Deb              ║
# ║   Android-in-Container on Debian · ARM64 / x86_64               ║
# ╚══════════════════════════════════════════════════════════════════╝
# Usage: bash redroid-lxc-setup.sh [--auto] [--android-ver 12]

set -euo pipefail

# ─── Palette ──────────────────────────────────────────────────────
RED='\033[0;31m';   YEL='\033[0;33m';  GRN='\033[0;32m'
CYN='\033[0;36m';   BLU='\033[0;34m';  MAG='\033[0;35m'
WHT='\033[1;37m';   DIM='\033[2m';     RST='\033[0m'
BOLD='\033[1m'

# ─── Helpers ──────────────────────────────────────────────────────
banner() {
  echo -e "${CYN}"
  cat << 'EOF'
  ██████╗ ███████╗██████╗ ██████╗  ██████╗ ██╗██████╗
  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗
  ██████╔╝█████╗  ██║  ██║██████╔╝██║   ██║██║██║  ██║
  ██╔══██╗██╔══╝  ██║  ██║██╔══██╗██║   ██║██║██║  ██║
  ██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝██║██████╔╝
  ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝
EOF
  echo -e "${DIM}  LXC Android Container Wizard · CyberMind SecuBox-Deb${RST}"
  echo -e "${DIM}  ────────────────────────────────────────────────────${RST}\n"
}

step() { echo -e "\n${BLU}▶${RST} ${BOLD}${1}${RST}"; }
ok()   { echo -e "  ${GRN}✓${RST} ${1}"; }
warn() { echo -e "  ${YEL}⚠${RST}  ${1}"; }
err()  { echo -e "  ${RED}✗${RST}  ${1}" >&2; }
ask()  { echo -en "  ${MAG}?${RST}  ${1} "; }

confirm() {
  ask "${1} [y/N]"
  read -r ans
  [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    err "Ce script doit être exécuté en root (ou via sudo)"
    exit 1
  fi
}

# ─── Détection architecture ───────────────────────────────────────
detect_arch() {
  ARCH=$(uname -m)
  case "$ARCH" in
    aarch64|arm64) HOST_ARCH="arm64"  ;;
    x86_64)        HOST_ARCH="amd64"  ;;
    *)
      err "Architecture non supportée: $ARCH"
      exit 1 ;;
  esac
  ok "Architecture hôte détectée : ${BOLD}${HOST_ARCH}${RST} (${ARCH})"
}

# ─── Vérification si dans LXC ─────────────────────────────────────
detect_lxc() {
  if grep -q "lxc" /proc/1/environ 2>/dev/null || \
     [[ -f /run/container_type ]] && grep -q "lxc" /run/container_type 2>/dev/null || \
     systemd-detect-virt --quiet --container 2>/dev/null | grep -q "lxc"; then
    IN_LXC=true
    ok "Environnement LXC détecté"
  else
    IN_LXC=false
    warn "Pas dans un LXC — vérification des paramètres nécessaire"
  fi
}

# ─── Vérification prérequis LXC (config côté host Proxmox/LXC) ───
check_lxc_config() {
  step "Vérification de la configuration LXC"

  # Binder devices
  local missing_devs=()
  for dev in binder hwbinder vndbinder; do
    if [[ -e "/dev/${dev}" ]] || [[ -e "/dev/binderfs/${dev}" ]]; then
      ok "/dev/${dev} disponible"
    else
      missing_devs+=("$dev")
      warn "/dev/${dev} ABSENT"
    fi
  done

  if [[ ${#missing_devs[@]} -gt 0 ]]; then
    echo -e "\n  ${YEL}Modules binder manquants. Sur l'hôte Proxmox/LXC, exécuter :${RST}"
    echo -e "  ${DIM}apt install linux-modules-extra-\$(uname -r)${RST}"
    echo -e "  ${DIM}modprobe binder_linux devices=\"binder,hwbinder,vndbinder\"${RST}"
    echo -e "  ${DIM}modprobe ashmem_linux${RST}"
    echo ""
    echo -e "  ${YEL}Ajouter dans /etc/pve/lxc/<CTID>.conf (Proxmox) :${RST}"
    cat << 'LXCCONF'
    lxc.cgroup2.devices.allow: c 10:* rwm
    lxc.mount.entry: /dev/binder    dev/binder    none bind,optional,create=file 0 0
    lxc.mount.entry: /dev/hwbinder  dev/hwbinder  none bind,optional,create=file 0 0
    lxc.mount.entry: /dev/vndbinder dev/vndbinder none bind,optional,create=file 0 0
LXCCONF
    echo ""
    if ! confirm "Continuer quand même ?"; then
      exit 0
    fi
  fi

  # Nesting / privileged
  if [[ -f /proc/sys/kernel/dmesg_restrict ]]; then
    ok "Kernel capabilities accessibles"
  fi
}

# ─── Installation Docker ──────────────────────────────────────────
install_docker() {
  step "Installation Docker"

  if command -v docker &>/dev/null; then
    ok "Docker déjà installé : $(docker --version)"
    return
  fi

  warn "Docker absent — installation en cours..."
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg lsb-release

  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg \
    | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg

  echo "deb [arch=$(dpkg --print-architecture) \
    signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian \
    $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list

  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
  ok "Docker installé : $(docker --version)"
}

# ─── Installation ADB + scrcpy ───────────────────────────────────
install_adb_scrcpy() {
  step "Installation ADB & scrcpy"

  if ! command -v adb &>/dev/null; then
    apt-get install -y -qq android-tools-adb
    ok "ADB installé"
  else
    ok "ADB déjà présent : $(adb --version | head -1)"
  fi

  if ! command -v scrcpy &>/dev/null; then
    apt-get install -y -qq scrcpy 2>/dev/null || {
      warn "scrcpy non dispo via apt — installation snap..."
      snap install scrcpy 2>/dev/null || warn "scrcpy non installé (headless OK)"
    }
  else
    ok "scrcpy déjà présent : $(scrcpy --version 2>&1 | head -1)"
  fi
}

# ─── Charger modules binder ───────────────────────────────────────
load_binder_modules() {
  step "Chargement des modules kernel binder"

  # Vérifier si dans LXC — si oui, les modules doivent exister côté hôte
  if [[ "$IN_LXC" == "true" ]]; then
    warn "Dans LXC : les modules doivent être chargés sur l'hôte, pas ici"
    warn "Si /dev/binder est absent, configurer l'hôte Proxmox d'abord"
    return
  fi

  for mod in binder_linux ashmem_linux; do
    if lsmod | grep -q "${mod%_linux}"; then
      ok "Module $mod chargé"
    else
      if modinfo "$mod" &>/dev/null; then
        modprobe "$mod" ${mod == "binder_linux" ? 'devices="binder,hwbinder,vndbinder"' : ''} 2>/dev/null && ok "Module $mod chargé" || warn "Impossible de charger $mod"
      else
        # Essayer via linux-modules-extra
        apt-get install -y -qq "linux-modules-extra-$(uname -r)" 2>/dev/null || true
        modprobe "$mod" 2>/dev/null && ok "Module $mod chargé" || warn "$mod non disponible"
      fi
    fi
  done

  # Persistance au reboot
  if ! grep -q "binder_linux" /etc/modules 2>/dev/null; then
    echo "binder_linux" >> /etc/modules
    echo "ashmem_linux" >> /etc/modules
    ok "Modules ajoutés à /etc/modules (persistance)"
  fi
}

# ─── Configuration réseau binderfs dans LXC ──────────────────────
setup_binderfs_lxc() {
  if [[ "$IN_LXC" == "true" ]] && [[ ! -e "/dev/binder" ]]; then
    step "Montage binderfs dans LXC"
    mkdir -p /dev/binderfs
    if ! mount -t binder binder /dev/binderfs 2>/dev/null; then
      err "Impossible de monter binderfs — vérifier la config LXC hôte"
      return 1
    fi
    ok "binderfs monté sur /dev/binderfs"
    # Créer des symlinks /dev/binder → /dev/binderfs/binder
    for dev in binder hwbinder vndbinder; do
      ln -sf "/dev/binderfs/${dev}" "/dev/${dev}" 2>/dev/null || true
    done
    ok "Symlinks /dev/binder* créés"
  fi
}

# ─── Choix de la version Android ─────────────────────────────────
choose_android_version() {
  step "Sélection de la version Android"

  local versions=("9" "10" "11" "12" "13" "15")
  local tags=(
    "redroid/redroid:9.0.0-latest"
    "redroid/redroid:10.0.0-latest"
    "redroid/redroid:11.0.0-latest"
    "redroid/redroid:12.0.0_64only-latest"
    "redroid/redroid:13.0.0-latest"
    "redroid/redroid:15.0.0_64only-latest"
  )
  local recs=(
    "stable, apps legacy"
    "stable"
    "recommandé + NDK ARM"
    "recommandé 64-bit"
    "stable récent"
    "latest"
  )

  echo ""
  for i in "${!versions[@]}"; do
    local marker=""
    [[ "${versions[$i]}" == "12" ]] && marker=" ${GRN}←${RST}"
    echo -e "  ${CYN}[${i}]${RST} Android ${BOLD}${versions[$i]}${RST}  ${DIM}${recs[$i]}${RST}${marker}"
  done
  echo ""

  if [[ "${AUTO_MODE:-false}" == "true" ]]; then
    ANDROID_IDX=3   # Android 12 par défaut
  else
    ask "Votre choix [0-5, défaut=3] :"
    read -r choice
    ANDROID_IDX=${choice:-3}
    [[ "$ANDROID_IDX" =~ ^[0-5]$ ]] || ANDROID_IDX=3
  fi

  ANDROID_VER="${versions[$ANDROID_IDX]}"
  DOCKER_IMAGE="${tags[$ANDROID_IDX]}"
  ok "Sélectionné : Android ${BOLD}${ANDROID_VER}${RST} → ${DIM}${DOCKER_IMAGE}${RST}"
}

# ─── Paramètres réseau / ports ────────────────────────────────────
choose_ports() {
  step "Configuration des ports"

  if [[ "${AUTO_MODE:-false}" == "true" ]]; then
    ADB_PORT=5555
    SCRCPY_PORT=5556
  else
    ask "Port ADB [défaut: 5555] :"
    read -r p; ADB_PORT=${p:-5555}
    ask "Nombre d'instances à démarrer [défaut: 1] :"
    read -r n; INSTANCE_COUNT=${n:-1}
  fi

  INSTANCE_COUNT=${INSTANCE_COUNT:-1}
  ok "Port ADB de base : ${BOLD}${ADB_PORT}${RST}  ×${INSTANCE_COUNT} instance(s)"
}

# ─── Options ARM translator ───────────────────────────────────────
choose_arm_translation() {
  if [[ "$HOST_ARCH" == "amd64" ]]; then
    step "Traduction ARM → x86 (NDK bridge)"
    echo -e "  ${DIM}Nécessaire pour faire tourner des APKs ARM sur hôte x86_64${RST}\n"

    if [[ "${AUTO_MODE:-false}" == "true" ]]; then
      USE_NDK=true
    else
      confirm "Activer libndk_translation (ARM apps sur x86) ?" && USE_NDK=true || USE_NDK=false
    fi

    [[ "$USE_NDK" == "true" ]] && ok "NDK ARM bridge activé" || warn "NDK désactivé (apps x86 seulement)"
  else
    USE_NDK=false
    ok "ARM64 natif — traduction inutile"
  fi
}

# ─── Génération docker-compose.yml ───────────────────────────────
generate_compose() {
  step "Génération de docker-compose.yml"

  local datadir="${REDROID_DATADIR:-/opt/redroid/data}"
  mkdir -p "$datadir"

  # Construire les binder volume mounts selon contexte
  local binder_vols=""
  if [[ "$IN_LXC" == "true" ]] && [[ -d "/dev/binderfs" ]]; then
    binder_vols='      - /dev/binderfs/binder:/dev/binder
      - /dev/binderfs/hwbinder:/dev/hwbinder
      - /dev/binderfs/vndbinder:/dev/vndbinder'
  fi

  # NDK extra props
  local ndk_props=""
  if [[ "${USE_NDK:-false}" == "true" ]]; then
    ndk_props='      - ro.product.cpu.abilist=x86_64,arm64-v8a,x86,armeabi-v7a,armeabi
      - ro.product.cpu.abilist64=x86_64,arm64-v8a
      - ro.product.cpu.abilist32=x86,armeabi-v7a,armeabi
      - ro.dalvik.vm.isa.arm=x86
      - ro.dalvik.vm.isa.arm64=x86_64
      - ro.enable.native.bridge.exec=1
      - ro.dalvik.vm.native.bridge=libndk_translation.so
      - ro.ndk_translation.version=0.2.2'
  fi

  # Générer N services
  local services=""
  for (( i=0; i<INSTANCE_COUNT; i++ )); do
    local port=$(( ADB_PORT + i ))
    local name="redroid-${i}"
    local vol="${datadir}/instance-${i}"
    mkdir -p "$vol"

    services+="
  ${name}:
    image: ${DOCKER_IMAGE}
    container_name: ${name}
    restart: unless-stopped
    tty: true
    stdin_open: true
    privileged: true
    ports:
      - \"127.0.0.1:${port}:5555\"
    volumes:
      - ${vol}:/data"

    if [[ -n "$binder_vols" ]]; then
      services+="
${binder_vols}"
    fi

    services+="
    command:
      - androidboot.redroid_width=1080
      - androidboot.redroid_height=1920
      - androidboot.redroid_dpi=480
      - androidboot.redroid_fps=60
      - androidboot.redroid_gpu_mode=guest"

    if [[ -n "$ndk_props" ]]; then
      services+="
${ndk_props}"
    fi

    services+="
"
  done

  cat > /opt/redroid/docker-compose.yml << YAML
# ══════════════════════════════════════════════════════════════════
#  ReDroid — Android in LXC Container
#  CyberMind SecuBox-Deb · Generated $(date '+%Y-%m-%d %H:%M')
#  Host arch : ${HOST_ARCH}   Android : ${ANDROID_VER}
#  Instances : ${INSTANCE_COUNT}   ADB base port : ${ADB_PORT}
# ══════════════════════════════════════════════════════════════════
services:
${services}
YAML

  ok "Fichier généré : /opt/redroid/docker-compose.yml"
}

# ─── Génération script de gestion ────────────────────────────────
generate_manager() {
  cat > /usr/local/bin/redroid-ctl << 'MGMT'
#!/usr/bin/env bash
# redroid-ctl — gestion des instances ReDroid
# Usage: redroid-ctl {start|stop|restart|status|connect|screen|shell|install} [instance]

COMPOSE_FILE="/opt/redroid/docker-compose.yml"
ADB_BASE=5555

_instances() {
  docker compose -f "$COMPOSE_FILE" ps --format json 2>/dev/null \
    | python3 -c "import sys,json; [print(c['Name']) for c in json.load(sys.stdin)]" 2>/dev/null \
    || docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null
}

_adb_connect_all() {
  local i=0
  for name in $(_instances); do
    local port=$(( ADB_BASE + i ))
    adb connect "127.0.0.1:${port}" 2>/dev/null && \
      echo "  ✓ ADB connecté : ${name} → 127.0.0.1:${port}"
    (( i++ ))
  done
}

case "${1:-help}" in
  start)
    echo "▶ Démarrage ReDroid..."
    cd /opt/redroid
    docker compose up -d
    sleep 5
    _adb_connect_all
    ;;
  stop)
    echo "▶ Arrêt ReDroid..."
    cd /opt/redroid && docker compose down
    adb disconnect 2>/dev/null || true
    ;;
  restart)
    $0 stop; sleep 2; $0 start
    ;;
  status)
    echo "══ Instances ReDroid ══"
    cd /opt/redroid && docker compose ps
    echo ""
    echo "══ Devices ADB ══"
    adb devices
    ;;
  connect)
    # Reconnect ADB
    adb disconnect 2>/dev/null || true
    sleep 1
    _adb_connect_all
    ;;
  screen)
    # Lancer scrcpy sur instance N (défaut: 0)
    local IDX="${2:-0}"
    local PORT=$(( ADB_BASE + IDX ))
    scrcpy -s "127.0.0.1:${PORT}" --window-title "ReDroid-${IDX}" &
    ;;
  shell)
    local IDX="${2:-0}"
    local PORT=$(( ADB_BASE + IDX ))
    adb -s "127.0.0.1:${PORT}" shell
    ;;
  install)
    # Installer un APK sur instance N
    # Usage: redroid-ctl install /path/to/app.apk [instance_idx]
    local APK="${2:?Usage: redroid-ctl install <apk> [idx]}"
    local IDX="${3:-0}"
    local PORT=$(( ADB_BASE + IDX ))
    adb -s "127.0.0.1:${PORT}" install -r "$APK"
    ;;
  logs)
    local IDX="${2:-0}"
    local NAME="redroid-${IDX}"
    docker logs -f "$NAME"
    ;;
  help|*)
    echo "Usage: redroid-ctl {start|stop|restart|status|connect|screen [N]|shell [N]|install <apk> [N]|logs [N]}"
    ;;
esac
MGMT

  chmod +x /usr/local/bin/redroid-ctl
  ok "Manager installé : /usr/local/bin/redroid-ctl"
}

# ─── Résumé final et démarrage ────────────────────────────────────
finalize() {
  step "Démarrage des conteneurs"

  cd /opt/redroid

  if confirm "Démarrer les instances maintenant ?"; then
    docker compose pull
    docker compose up -d

    echo -e "\n  ${YEL}Attente boot Android (~15s)...${RST}"
    sleep 15

    # Connexion ADB
    for (( i=0; i<INSTANCE_COUNT; i++ )); do
      local port=$(( ADB_PORT + i ))
      adb connect "127.0.0.1:${port}" && ok "ADB connecté sur 127.0.0.1:${port}" \
        || warn "ADB: tentative manuelle recommandée"
    done
  fi

  echo -e "\n${CYN}╔══════════════════════════════════════════════════╗${RST}"
  echo -e "${CYN}║${RST}  ${BOLD}ReDroid LXC · Déploiement terminé${RST}              ${CYN}║${RST}"
  echo -e "${CYN}╚══════════════════════════════════════════════════╝${RST}"
  echo ""
  echo -e "  ${GRN}Commandes disponibles :${RST}"
  echo -e "  ${CYN}redroid-ctl start${RST}          — démarrer"
  echo -e "  ${CYN}redroid-ctl status${RST}         — état + ADB devices"
  echo -e "  ${CYN}redroid-ctl screen [N]${RST}     — affichage scrcpy"
  echo -e "  ${CYN}redroid-ctl shell [N]${RST}      — shell adb"
  echo -e "  ${CYN}redroid-ctl install app.apk${RST}— installer un APK"
  echo -e "  ${CYN}redroid-ctl logs [N]${RST}       — logs temps réel"
  echo ""
  echo -e "  ${DIM}Compose : /opt/redroid/docker-compose.yml${RST}"
  echo -e "  ${DIM}Data    : /opt/redroid/data/${RST}"
  echo ""
}

# ─── Main ─────────────────────────────────────────────────────────
main() {
  AUTO_MODE=false
  ANDROID_VER_OVERRIDE=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --auto)          AUTO_MODE=true ;;
      --android-ver)   ANDROID_VER_OVERRIDE="$2"; shift ;;
      --instances)     INSTANCE_COUNT="$2"; shift ;;
      --port)          ADB_PORT="$2"; shift ;;
      --help|-h)
        echo "Usage: $0 [--auto] [--android-ver {9|10|11|12|13|15}] [--instances N] [--port PORT]"
        exit 0 ;;
    esac
    shift
  done

  banner
  require_root
  detect_arch
  detect_lxc
  check_lxc_config
  install_docker
  install_adb_scrcpy
  load_binder_modules
  setup_binderfs_lxc
  choose_android_version
  choose_ports
  choose_arm_translation
  generate_compose
  generate_manager
  finalize
}

main "$@"
