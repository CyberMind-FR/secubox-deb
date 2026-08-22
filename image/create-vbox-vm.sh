#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# ══════════════════════════════════════════════════════════════════
#  SecuBox-DEB :: create-vbox-vm.sh — script VirtualBox CANONIQUE
#
#  Crée (et démarre) une VM VirtualBox à partir de l'image live-USB
#  amd64 de SecuBox. Remplace run-vbox.sh, create-secubox-vm.sh et
#  vbox-setup.sh — ceux-ci ne sont plus que des redirections.
#
#  VirtualBox est amd64 uniquement : il démarre l'image
#  `secubox-live-amd64-*`, PAS les images ARM64 (mochabin/rpi), qui
#  passent par QEMU (voir scripts/run-qemu.sh).
#
#  Usage :
#    bash image/create-vbox-vm.sh                     # image locale output/
#    bash image/create-vbox-vm.sh --download          # dernière release
#    bash image/create-vbox-vm.sh --download v3.0.0-alpha.1
#    bash image/create-vbox-vm.sh output/secubox-live-amd64-bookworm.img
#    bash image/create-vbox-vm.sh img.vdi --name Test --headless
# ══════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="${REPO_DIR}/output"
GITHUB_REPO="CyberMind-FR/secubox-deb"

# ── Défauts ──────────────────────────────────────────────────────
VM_NAME="SecuBox-Live"
VM_RAM=4096
VM_CPUS=4
VM_VRAM=128
SSH_PORT=2222
HTTPS_PORT=9443
HTTP_PORT=8080
IMAGE=""            # chemin explicite (.img/.img.gz/.vdi) ; sinon auto
DOWNLOAD=""         # "" | "latest" | un tag de release
HEADLESS=0
NO_START=0
FORCE=0

RED='\033[0;31m'; CYAN='\033[0;36m'; GOLD='\033[0;33m'
GREEN='\033[0;32m'; NC='\033[0m'

# Une IMAGE réelle finit par .img ou .img.gz — surtout PAS .sha256/.sig/.vdi
# (sidecars qui matcheraient un glob « *.img* » trop gourmand). Rend la plus
# récente correspondant au préfixe, ou une chaîne vide.
newest_image() { ls -t "$1"* 2>/dev/null | grep -E '\.img(\.gz)?$' | head -1 || true; }
log()  { echo -e "${CYAN}[vbox]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }
warn() { echo -e "${GOLD}[warn ]${NC} $*"; }
err()  { echo -e "${RED}[FAIL ]${NC} $*" >&2; exit 1; }

usage() {
    cat <<EOF
SecuBox — create-vbox-vm.sh

Crée et démarre une VM VirtualBox depuis l'image live-USB amd64.

Usage: $(basename "$0") [OPTIONS] [IMAGE]

  IMAGE                 Chemin d'une image .img, .img.gz ou .vdi.
                        Omis → dernière secubox-live-amd64-*.img* dans output/.

Options:
  --download [TAG]      Télécharge l'image depuis les releases GitHub avant
                        (TAG optionnel, ex. v3.0.0-alpha.1 ; défaut : la
                        dernière release). Nécessite gh, sinon curl/wget.
  -n, --name NAME       Nom de la VM (défaut: $VM_NAME)
  -m, --memory MB       RAM (défaut: $VM_RAM)
  -c, --cpus N          vCPU (défaut: $VM_CPUS)
      --vram MB         VRAM (défaut: $VM_VRAM)
  -s, --ssh PORT        Port hôte → 22 invité (défaut: $SSH_PORT)
  -w, --https PORT      Port hôte → 443 invité (défaut: $HTTPS_PORT)
      --http PORT       Port hôte → 80 invité (défaut: $HTTP_PORT)
      --headless        Démarre sans fenêtre
      --no-start        Crée la VM sans la démarrer
  -f, --force, --delete Supprime la VM existante puis recrée
  -h, --help            Cette aide

Redirection de ports (NAT):
  SSH:   ssh -p $SSH_PORT root@localhost
  HTTPS: https://localhost:$HTTPS_PORT
  HTTP:  http://localhost:$HTTP_PORT
EOF
    exit 0
}

# ── Options ──────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --download)
            DOWNLOAD="latest"
            # Argument optionnel : un tag (ne commence pas par '-').
            if [[ $# -ge 2 && "$2" != -* ]]; then DOWNLOAD="$2"; shift; fi
            shift ;;
        -n|--name)    VM_NAME="$2"; shift 2 ;;
        -m|--memory)  VM_RAM="$2"; shift 2 ;;
        -c|--cpus)    VM_CPUS="$2"; shift 2 ;;
        --vram)       VM_VRAM="$2"; shift 2 ;;
        -s|--ssh)     SSH_PORT="$2"; shift 2 ;;
        -w|--https)   HTTPS_PORT="$2"; shift 2 ;;
        --http)       HTTP_PORT="$2"; shift 2 ;;
        --headless)   HEADLESS=1; shift ;;
        --no-start)   NO_START=1; shift ;;
        -f|--force|--delete) FORCE=1; shift ;;
        -h|--help)    usage ;;
        -*)           err "Option inconnue : $1 (voir --help)" ;;
        *)            IMAGE="$1"; shift ;;
    esac
done

command -v VBoxManage &>/dev/null || err "VBoxManage introuvable — installe VirtualBox."

# ── Résolution de l'image ────────────────────────────────────────
download_image() {
    local tag="$1" dest
    mkdir -p "$OUTPUT_DIR"
    if command -v gh &>/dev/null; then
        local args=(release download --repo "$GITHUB_REPO" --dir "$OUTPUT_DIR"
                    --pattern '*live-amd64*.img*' --clobber)
        [[ "$tag" != "latest" ]] && args+=("$tag")
        log "Téléchargement via gh (${tag})…"
        gh "${args[@]}" || err "gh release download a échoué (tag ${tag} ?)."
        # La plus récente image amd64 fraîchement récupérée (hors .sha256/.sig).
        IMAGE="$(newest_image "${OUTPUT_DIR}/secubox-live-amd64")"
    else
        warn "gh absent — repli sur l'URL 'latest' (curl/wget)."
        [[ "$tag" != "latest" ]] && warn "Tag ${tag} ignoré sans gh (URL latest)."
        dest="${OUTPUT_DIR}/secubox-live-amd64-bookworm.img.gz"
        local url="https://github.com/${GITHUB_REPO}/releases/latest/download/secubox-live-amd64-bookworm.img.gz"
        if command -v curl &>/dev/null; then curl -fL --progress-bar -o "$dest" "$url"
        elif command -v wget &>/dev/null; then wget -q --show-progress -O "$dest" "$url"
        else err "curl ou wget requis pour --download."; fi
        IMAGE="$dest"
    fi
    [[ -n "$IMAGE" && -f "$IMAGE" ]] || err "Aucune image amd64 téléchargée."
    ok "Image : $IMAGE"
}

if [[ -n "$DOWNLOAD" ]]; then
    download_image "$DOWNLOAD"
elif [[ -z "$IMAGE" ]]; then
    # Auto : la plus récente image amd64 dans output/ (hors sidecars .sha256).
    IMAGE="$(newest_image "${OUTPUT_DIR}/secubox-live-amd64")"
    [[ -n "$IMAGE" ]] || err "Aucune image amd64 (.img/.img.gz) dans ${OUTPUT_DIR}. Utilise --download ou donne un chemin."
    log "Image auto-détectée : $IMAGE"
fi
[[ -f "$IMAGE" ]] || err "Image introuvable : $IMAGE"

# ── .img.gz → .img ───────────────────────────────────────────────
if [[ "$IMAGE" == *.gz ]]; then
    local_img="${IMAGE%.gz}"
    if [[ ! -f "$local_img" || "$IMAGE" -nt "$local_img" ]]; then
        log "Décompression $(basename "$IMAGE")…"
        gunzip -kf "$IMAGE"
    fi
    IMAGE="$local_img"
fi

# ── image brute → VDI (une .vdi est utilisée telle quelle) ───────
if [[ "$IMAGE" == *.vdi ]]; then
    VDI="$(realpath "$IMAGE")"
else
    VDI="${IMAGE%.*}.vdi"
    if [[ ! -f "$VDI" || "$IMAGE" -nt "$VDI" ]]; then
        log "Conversion raw → VDI…"
        # Réécrire le fichier lui donne un NOUVEL UUID : on retire d'abord toute
        # inscription périmée de ce chemin du registre média, sinon VirtualBox
        # refuse au boot (« UUID … does not match … media registry »).
        VBoxManage closemedium disk "$VDI" &>/dev/null || true
        rm -f "$VDI"
        VBoxManage convertfromraw "$IMAGE" "$VDI" --format VDI
    else
        log "VDI existant réutilisé : $(basename "$VDI")"
    fi
    VDI="$(realpath "$VDI")"
fi
ok "Disque VDI : $VDI"

# Garde-fou : purge toute inscription périmée de ce chemin avant l'attache. Le
# storageattach ré-enregistre le médium avec son UUID réel — plus de conflit
# d'UUID hérité d'un ancien run ou d'un autre script.
VBoxManage closemedium disk "$VDI" &>/dev/null || true

# ── VM existante ─────────────────────────────────────────────────
if VBoxManage showvminfo "$VM_NAME" &>/dev/null; then
    if [[ "$FORCE" -eq 1 ]]; then
        log "Suppression de la VM existante « $VM_NAME »…"
        VBoxManage controlvm "$VM_NAME" poweroff &>/dev/null || true
        sleep 1
        # Détacher le disque AVANT --delete : le VDI vit dans output/ et est
        # partagé entre runs ; --delete supprimerait sinon le fichier image.
        VBoxManage storageattach "$VM_NAME" --storagectl "SATA" \
            --port 0 --device 0 --medium none &>/dev/null || true
        VBoxManage unregistervm "$VM_NAME" --delete &>/dev/null || true
    else
        err "La VM « $VM_NAME » existe déjà — relance avec --force pour la recréer."
    fi
fi

# ── Création + configuration ─────────────────────────────────────
log "Création de la VM « $VM_NAME »…"
VBoxManage createvm --name "$VM_NAME" --ostype "Debian_64" --register

VBoxManage modifyvm "$VM_NAME" \
    --memory "$VM_RAM" \
    --cpus "$VM_CPUS" \
    --vram "$VM_VRAM" \
    --graphicscontroller vmsvga \
    --firmware efi64 \
    --chipset ich9 \
    --boot1 disk --boot2 none \
    --nic1 nat --nictype1 virtio \
    --natpf1 "SSH,tcp,,${SSH_PORT},,22" \
    --natpf1 "HTTPS,tcp,,${HTTPS_PORT},,443" \
    --natpf1 "HTTP,tcp,,${HTTP_PORT},,80" \
    --audio-enabled off \
    --usb-ehci off --usb-xhci on \
    --clipboard-mode bidirectional

VBoxManage storagectl "$VM_NAME" --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach "$VM_NAME" \
    --storagectl "SATA" --port 0 --device 0 --type hdd --medium "$VDI"

# ── Récapitulatif ────────────────────────────────────────────────
cat <<EOF

${GREEN}══════════════════════════════════════════════════════════${NC}
  SecuBox VirtualBox — VM prête
${GREEN}══════════════════════════════════════════════════════════${NC}
  Nom     : ${VM_NAME}
  RAM/CPU : ${VM_RAM} Mo / ${VM_CPUS} vCPU
  Disque  : ${VDI}

  Accès (après démarrage) :
    SSH   : ssh -p ${SSH_PORT} root@localhost
    HTTPS : https://localhost:${HTTPS_PORT}
    HTTP  : http://localhost:${HTTP_PORT}
  Identifiants par défaut : root / secubox
══════════════════════════════════════════════════════════
EOF

# ── Démarrage ────────────────────────────────────────────────────
if [[ "$NO_START" -eq 1 ]]; then
    log "VM créée, non démarrée (--no-start). Démarrer : VBoxManage startvm \"$VM_NAME\""
    exit 0
fi
if [[ "$HEADLESS" -eq 1 ]]; then
    log "Démarrage headless…"
    VBoxManage startvm "$VM_NAME" --type headless
    log "Arrêt : VBoxManage controlvm \"$VM_NAME\" poweroff"
else
    log "Démarrage (fenêtre)…"
    VBoxManage startvm "$VM_NAME" --type gui
fi
ok "Patiente 30–60 s le temps du boot."
