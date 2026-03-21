#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB — create-vbox-vm.sh
#  Crée une VM VirtualBox prête à l'emploi avec l'image SecuBox
#  Usage : bash create-vbox-vm.sh [IMAGE.vdi]
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"

# Defaults
VM_NAME="SecuBox-Dev"
VM_RAM=2048
VM_CPUS=2
VM_DISK_SIZE=8192  # MB

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'

log()  { echo -e "${CYAN}[vbox]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: bash create-vbox-vm.sh [OPTIONS] [IMAGE.vdi]

Options:
  --name NAME      Nom de la VM (défaut: SecuBox-Dev)
  --ram  MB        RAM en MB (défaut: 2048)
  --cpus N         Nombre de CPUs (défaut: 2)
  --help           Cette aide

Si aucune image n'est fournie, une nouvelle VM est créée avec un disque vide.
Sinon, le .vdi fourni est utilisé.

Configuration réseau VirtualBox recommandée :
  - Adapter 1 : NAT (pour accès internet - WAN)
  - Adapter 2 : Host-Only ou Internal Network (pour accès LAN)

EOF
  exit 0
}

# Parse args
VDI_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)   VM_NAME="$2";  shift 2 ;;
    --ram)    VM_RAM="$2";   shift 2 ;;
    --cpus)   VM_CPUS="$2";  shift 2 ;;
    --help|-h) usage ;;
    *.vdi)    VDI_FILE="$1"; shift ;;
    *.img)
      # Convertir l'image raw en vdi
      log "Conversion de $1 en VDI..."
      VDI_FILE="${1%.img}.vdi"
      qemu-img convert -f raw -O vdi "$1" "$VDI_FILE"
      shift
      ;;
    *) err "Argument inconnu: $1" ;;
  esac
done

# Vérifier VBoxManage
command -v VBoxManage >/dev/null || err "VBoxManage non trouvé. Installer VirtualBox."

log "Création VM: ${BOLD}${VM_NAME}${NC}"
log "RAM: ${VM_RAM} MB | CPUs: ${VM_CPUS}"

# Vérifier si VM existe déjà
if VBoxManage showvminfo "${VM_NAME}" &>/dev/null; then
  err "Une VM nommée '${VM_NAME}' existe déjà. Supprimer ou choisir un autre nom."
fi

# Créer la VM
VBoxManage createvm --name "${VM_NAME}" --ostype "Debian_64" --register

# Configurer système
VBoxManage modifyvm "${VM_NAME}" \
  --memory "${VM_RAM}" \
  --cpus "${VM_CPUS}" \
  --firmware efi64 \
  --graphicscontroller vmsvga \
  --vram 32 \
  --audio none \
  --boot1 disk --boot2 none --boot3 none --boot4 none

# Configurer réseau : 2 interfaces
# Adapter 1 : NAT (WAN)
VBoxManage modifyvm "${VM_NAME}" \
  --nic1 nat \
  --nictype1 virtio \
  --cableconnected1 on

# Adapter 2 : Host-Only (LAN) - créer si nécessaire
HOSTONLY_NET=$(VBoxManage list hostonlyifs | grep "^Name:" | head -1 | awk '{print $2}')
if [[ -z "$HOSTONLY_NET" ]]; then
  log "Création interface Host-Only..."
  VBoxManage hostonlyif create
  HOSTONLY_NET=$(VBoxManage list hostonlyifs | grep "^Name:" | head -1 | awk '{print $2}')
fi

VBoxManage modifyvm "${VM_NAME}" \
  --nic2 hostonly \
  --hostonlyadapter2 "${HOSTONLY_NET}" \
  --nictype2 virtio \
  --cableconnected2 on

log "Réseau configuré : NAT (WAN) + Host-Only (LAN)"

# Créer contrôleur SATA
VBoxManage storagectl "${VM_NAME}" \
  --name "SATA" \
  --add sata \
  --controller IntelAhci \
  --portcount 2

# Disque
VM_DIR=$(VBoxManage showvminfo "${VM_NAME}" --machinereadable | grep "^CfgFile=" | cut -d'"' -f2 | xargs dirname)

if [[ -n "$VDI_FILE" ]] && [[ -f "$VDI_FILE" ]]; then
  # Utiliser le VDI fourni (copier dans le dossier VM)
  DISK_PATH="${VM_DIR}/${VM_NAME}.vdi"
  cp "$VDI_FILE" "$DISK_PATH"
  log "Disque copié depuis $VDI_FILE"
else
  # Créer un nouveau disque
  DISK_PATH="${VM_DIR}/${VM_NAME}.vdi"
  VBoxManage createmedium disk --filename "$DISK_PATH" --size "${VM_DISK_SIZE}" --format VDI
  log "Nouveau disque créé : ${VM_DISK_SIZE} MB"
fi

# Attacher le disque
VBoxManage storageattach "${VM_NAME}" \
  --storagectl "SATA" \
  --port 0 \
  --device 0 \
  --type hdd \
  --medium "$DISK_PATH"

ok "VM '${VM_NAME}' créée avec succès !"
echo ""
echo -e "${GOLD}${BOLD}════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  VM VirtualBox SecuBox prête !${NC}"
echo ""
echo "  Démarrer : VBoxManage startvm '${VM_NAME}'"
echo "  GUI      : VBoxManage startvm '${VM_NAME}' --type gui"
echo "  Headless : VBoxManage startvm '${VM_NAME}' --type headless"
echo ""
echo "  Réseau :"
echo "    - enp0s3 (NAT)       : Accès internet (WAN)"
echo "    - enp0s8 (Host-Only) : 192.168.100.1 (LAN SecuBox)"
echo ""
echo "  Accès SSH : ssh root@<ip-host-only>"
echo "  Web UI    : http://<ip-host-only>/"
echo -e "${GOLD}${BOLD}════════════════════════════════════════════${NC}"
