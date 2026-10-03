#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.

# SecuBox-Deb :: secubox-voicestudio :: install-lxc.sh (#1917, ex-#1649)
#
# Crée (idempotent) le LXC `voicestudio` : Debian bookworm non privilégié, IP fixe
# sur br-lxc, moteur VoiceStudio installé dans un venv Python (torch CPU), sources
# amont ÉPINGLÉES par commit et vérifiées par empreinte sha256.
#
# DISPOSITION IDENTIQUE À L'IMAGE OFFICIELLE : sources dans /app, données dans
# /app/omnivoice_data (montage hôte). La base SQLite du moteur garde des chemins
# absolus : migrer un volume podman existant exige donc le MÊME chemin dans le LXC.
#
# L'interface native (frontend/dist, 12 Mo) est produite par un build Node absent de
# l'archive amont ; les panneaux SecuBox (/voicestudio/) la remplacent, on n'embarque
# donc pas Node dans le conteneur. Le moteur démarre sans elle.
#
# Appelé par `voicestudioctl install` ; lit /etc/secubox/voicestudio.toml.
# shellcheck disable=SC2016  # les arguments de sh -c sont VOLONTAIREMENT entre apostrophes (expansion dans le conteneur)
set -euo pipefail

readonly CONF="${SECUBOX_VS_CONF:-/etc/secubox/voicestudio.toml}"
readonly CONTRAINTES="${SECUBOX_VS_CONTRAINTES:-/usr/share/secubox/voicestudio/contraintes.txt}"
readonly STATE_DIR="${SECUBOX_VS_ETAT_DIR:-/var/lib/secubox/voicestudio}"
readonly SENTINEL="$STATE_DIR/.lxc-provisioned"
readonly LXC_BRIDGE="${SECUBOX_LXC_BRIDGE:-br-lxc}"
readonly LXC_GW="${SECUBOX_LXC_GW:-10.100.0.1}"
readonly LXC_ROOT_UID="${SECUBOX_LXC_ROOT_UID:-100000}"
readonly PORT=3900
log() { printf '[voicestudio-install] %s\n' "$*"; }

cfg() {  # cfg <section> <clé> [défaut]
  python3 - "$CONF" "$1" "$2" "${3:-}" <<'PY'
import sys, tomllib
p, sec, cle, defaut = sys.argv[1:5]
try:
    with open(p, "rb") as f:
        v = tomllib.load(f).get(sec, {}).get(cle, defaut)
except OSError:
    v = defaut
print(v)
PY
}

LXC_NAME="$(cfg lxc nom voicestudio)"
LXC_PATH="$(cfg lxc chemin /data/lxc)"
LXC_IP="$(cfg lxc ip 10.100.0.230)"
MEMOIRE="$(cfg lxc memoire 4G)"
CPU_POIDS="$(cfg lxc cpu_poids 50)"
DONNEES="$(cfg lxc donnees /srv/secubox/voicestudio)"
COMMIT="$(cfg source commit)"
SHA256="$(cfg source sha256)"
DEPOT="$(cfg source depot https://github.com/debpalash/VoiceStudio)"
ASR="$(cfg moteur asr Systran/faster-whisper-base)"
ACTIVER_INTERFACE="$(cfg interface activer true)"
BUN_URL="$(cfg interface bun_url)"
BUN_SHA256="$(cfg interface bun_sha256)"
BUN_VERSION="$(cfg interface bun_version)"
MODE_INTERFACE=0
[ "${1:-}" = "--interface" ] && MODE_INTERFACE=1
readonly VETH="veth-vstudio0"
readonly LXC_NAME LXC_PATH LXC_IP MEMOIRE CPU_POIDS DONNEES COMMIT SHA256 DEPOT ASR

if [ -z "$COMMIT" ] || [ -z "$SHA256" ]; then
  log "source.commit / source.sha256 absents de $CONF"
  exit 1
fi
[ "$(dpkg --print-architecture)" = "amd64" ] || {
  log "VoiceStudio n'a de roues torch/onnxruntime que pour amd64 ici : box $(dpkg --print-architecture) non prise en charge"
  exit 3
}

la() { lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- "$@"; }

mkdir -p "$STATE_DIR" "$DONNEES"
chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$DONNEES"
chmod 0750 "$DONNEES"

creer_conteneur() {
  lxc-create -n "$LXC_NAME" -t download -P "$LXC_PATH" -- \
    --dist debian --release bookworm --arch "$(dpkg --print-architecture)"
  if ! grep -q '^lxc.idmap' "$LXC_PATH/$LXC_NAME/config"; then
    printf 'lxc.idmap = u 0 %s 65536\nlxc.idmap = g 0 %s 65536\n' "$LXC_ROOT_UID" "$LXC_ROOT_UID" \
      >> "$LXC_PATH/$LXC_NAME/config"
  fi
  cat >> "$LXC_PATH/$LXC_NAME/config" <<CFG
lxc.net.0.type = veth
lxc.net.0.link = $LXC_BRIDGE
lxc.net.0.flags = up
lxc.net.0.veth.pair = $VETH
lxc.net.0.ipv4.address = $LXC_IP/24
lxc.net.0.ipv4.gateway = $LXC_GW

# Le mode (permanent / à la demande) est appliqué par voicestudioctl : il réécrit
# lxc.start.auto, le plafond mémoire et le poids CPU entre les marques ci-dessous.
# >>> secubox-voicestudio
lxc.start.auto = 1
lxc.cgroup2.memory.max = $MEMOIRE
lxc.cgroup2.cpu.weight = $CPU_POIDS
# <<< secubox-voicestudio

# Données du moteur (voix, historique, modèles, base SQLite) sur le stockage de
# l'hôte : survivent à un reprovisionnement. Même chemin que dans l'image amont.
lxc.mount.entry = $DONNEES app/omnivoice_data none bind,create=dir 0 0
CFG
  # Le rootfs déballé est à l'uid 0 de l'HÔTE ; l'idmap veut 100000 (cf. ytsas, #1308).
  if [ "$(stat -c %u "$LXC_PATH/$LXC_NAME/rootfs")" = "0" ]; then
    chown -R "$LXC_ROOT_UID:$LXC_ROOT_UID" "$LXC_PATH/$LXC_NAME/rootfs"
    chown "$LXC_ROOT_UID:$LXC_ROOT_UID" "$LXC_PATH/$LXC_NAME"
  fi
}

demarrer() {
  lxc-info -P "$LXC_PATH" -n "$LXC_NAME" -sH 2>/dev/null | grep -q RUNNING \
    || lxc-start -n "$LXC_NAME" -P "$LXC_PATH" -d
  for _ in $(seq 1 30); do
    la true 2>/dev/null && break
    sleep 1
  done
}

# INTERFACE NATIVE. L'archive amont ne contient pas `frontend/dist` : c'est un build React/Vite, que le Dockerfile
# amont produit avec bun (`bun install --frozen-lockfile` puis `bun run --cwd frontend build`, lockfile à la racine du
# monorepo). On refait EXACTEMENT cela dans le LXC, avec un bun épinglé (version + sha256), puis on le supprime : il
# n'en reste que `dist` (12 Mo). Pic de mémoire mesuré : 2 Go pendant 2 s (plafond du LXC : 4G). Idempotent : un dist
# présent n'est pas reconstruit (`--interface` après une mise à jour d'amont : supprimer /app/frontend/dist avant).
# Le travail proprement dit, dans le LXC : bun épinglé et vérifié, installation figée, construction, nettoyage.
construire_interface_dans_le_lxc() {
  la env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends unzip ca-certificates curl
  la sh -c 'curl -fsSL --retry 3 -o /tmp/bun.zip "$1"' _ "$BUN_URL"
  # L'empreinte AVANT de déplier : un binaire qui ne correspond pas à celui relu n'est jamais exécuté.
  la sh -c 'echo "$1  /tmp/bun.zip" | sha256sum -c -' _ "$BUN_SHA256" \
    || { log "empreinte sha256 de bun INVALIDE — abandon"; return 4; }
  la sh -c 'set -e
    rm -rf /tmp/fb /opt/bun && mkdir -p /tmp/fb/frontend /opt/bun
    unzip -q -o /tmp/bun.zip -d /opt/bun
    B="$(find /opt/bun -name bun -type f | head -1)"
    cp /app/package.json /app/bun.lock /tmp/fb/
    cp -r /app/frontend/. /tmp/fb/frontend/
    cd /tmp/fb
    "$B" install --frozen-lockfile
    "$B" run --cwd frontend build
    test -s frontend/dist/index.html
    rm -rf /app/frontend/dist && cp -r frontend/dist /app/frontend/dist
    rm -rf /tmp/fb /opt/bun /tmp/bun.zip /root/.bun /root/.cache'
}

construire_interface() {
  if [ "$ACTIVER_INTERFACE" != "True" ]; then
    log "interface native désactivée ([interface] activer = false)"
    return 0
  fi
  if la test -s /app/frontend/dist/index.html; then
    log "interface native déjà construite"
    return 0
  fi
  if [ -z "$BUN_URL" ] || [ -z "$BUN_SHA256" ]; then
    log "[interface] bun_url / bun_sha256 absents de $CONF"
    return 1
  fi
  log "construction de l'interface native (bun $BUN_VERSION)…"
  # Mémoire : le moteur (≈ 600 Mo) est arrêté PENDANT la construction (pic ≈ 2 Go) puis relancé quoi qu'il arrive — gk3 n'a
  # pas de quoi tenir les deux sans swap.
  etait_actif=0
  if la systemctl is-active -q voicestudio.service; then
    etait_actif=1
    la systemctl stop voicestudio.service || true
  fi
  rc=0
  construire_interface_dans_le_lxc || rc=$?
  if [ "$etait_actif" = 1 ]; then la systemctl start voicestudio.service || true; fi
  if [ "$rc" != 0 ]; then
    log "construction de l'interface native EN ÉCHEC (rc=$rc) ; le moteur est relancé sans elle"
    return "$rc"
  fi
  log "interface native construite"
}


if [ "$MODE_INTERFACE" = 1 ]; then
  [ -d "$LXC_PATH/$LXC_NAME" ] || { log "LXC absent — voicestudioctl install d'abord"; exit 1; }
  demarrer
  construire_interface
  exit $?
fi

if [ ! -f "$SENTINEL" ]; then
  [ -d "$LXC_PATH/$LXC_NAME" ] || creer_conteneur
  demarrer
  sleep 4
  la sh -c 'rm -f /etc/resolv.conf; printf "nameserver 1.1.1.1\nnameserver 9.9.9.9\n" > /etc/resolv.conf'
  la apt-get update
  la env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip ffmpeg libsndfile1 librubberband2 libsoxr0 ca-certificates curl

  log "téléchargement des sources $COMMIT"
  # Valeurs passées en ARGUMENTS POSITIONNELS de sh -c, jamais interpolées dans la chaîne : un TOML
  # altéré ne peut pas injecter de commande.
  la sh -c 'curl -fsSL --retry 3 -o /tmp/voicestudio.tgz "$1/archive/$2.tar.gz"' _ "$DEPOT" "$COMMIT"
  # Empreinte AVANT toute extraction : une archive qui ne correspond pas à celle que nous avons
  # relue n'est jamais dépliée (si GitHub régénère l'archive, l'installation échoue FERMÉE).
  la sh -c 'echo "$1  /tmp/voicestudio.tgz" | sha256sum -c -' _ "$SHA256" \
    || { log "empreinte sha256 de l'archive INVALIDE — abandon"; exit 4; }
  # Chemins absolus ou « .. » refusés, liens sortants refusés, nombre d'entrées plafonné.
  la sh -c '! tar tzf /tmp/voicestudio.tgz | grep -qE "(^/|(^|/)\.\.(/|$))"' \
    || { log "l'archive contient un chemin sortant — abandon"; exit 4; }
  la sh -c '! tar tvzf /tmp/voicestudio.tgz | awk "/^[lh]/" | grep -qE "( -> | link to )(/|.*\.\.)"' \
    || { log "l'archive contient un lien sortant — abandon"; exit 4; }
  la sh -c '[ "$(tar tzf /tmp/voicestudio.tgz | wc -l)" -le 50000 ]' \
    || { log "l'archive contient trop d'entrées — abandon"; exit 4; }
  # Une réinstallation repart d'un /app propre (les données, montées à part, ne sont pas touchées).
  la sh -c 'mkdir -p /app && find /app -mindepth 1 -maxdepth 1 ! -name omnivoice_data -exec rm -rf {} + && \
    tar xzf /tmp/voicestudio.tgz --strip-components=1 --no-same-owner -C /app && rm -f /tmp/voicestudio.tgz'

  # Contraintes tirées de l'image qui tournait : mêmes versions que celles validées.
  lxc-attach -n "$LXC_NAME" -P "$LXC_PATH" -- sh -c 'cat > /root/contraintes.txt' < "$CONTRAINTES"
  la python3 -m venv /opt/venv
  la /opt/venv/bin/pip install --no-cache-dir --upgrade pip wheel
  log "installation de torch (CPU) puis des dépendances — long (10 à 25 minutes)"
  # torch/torchaudio/torchvision viennent de l'index PyTorch SEUL (--index-url, pas --extra-index-url :
  # un nom présent des deux côtés ne peut pas être « confondu » avec PyPI) ; tout le reste vient de PyPI.
  la /opt/venv/bin/pip install --no-cache-dir --no-deps -c /root/contraintes.txt \
    --index-url https://download.pytorch.org/whl/cpu \
    torch==2.8.0 torchaudio==2.8.0 torchvision==0.23.0
  la /opt/venv/bin/pip install --no-cache-dir -c /root/contraintes.txt /app
  la /opt/venv/bin/pip check
  construire_interface
  echo "$COMMIT" > "$STATE_DIR/commit-installe"
fi

demarrer

# Environnement du moteur. La CLÉ D'API n'est pas écrite ici : `voicestudioctl`
# la pousse (clé de l'hôte, jamais dans un TOML versionné).
la sh -c 'cat > /etc/voicestudio.env.base && chmod 0600 /etc/voicestudio.env.base' <<ENV
OMNIVOICE_SERVER_MODE=1
OMNIVOICE_BIND_HOST=$LXC_IP
OMNIVOICE_DATA_DIR=/app/omnivoice_data
HF_HOME=/app/omnivoice_data/huggingface
OMNIVOICE_ASR_BACKEND=faster-whisper
ASR_MODEL_FASTER=$ASR
PYTHONPATH=/app/backend
PYTHONUNBUFFERED=1
PYTHONDONTWRITEBYTECODE=1
PIP_BREAK_SYSTEM_PACKAGES=1
ENV
la sh -c 'cat > /etc/systemd/system/voicestudio.service' <<UNIT
[Unit]
Description=VoiceStudio (moteur vocal studio) — SecuBox
After=network.target

[Service]
Type=simple
WorkingDirectory=/app
# env.base = réglages (posés par install-lxc.sh) ; voicestudio.env = clé d'API (poussée par voicestudioctl)
EnvironmentFile=/etc/voicestudio.env.base
EnvironmentFile=-/etc/voicestudio.env
ExecStart=/opt/venv/bin/python -m uvicorn backend.main:app --host $LXC_IP --port $PORT
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
UNIT
la systemctl daemon-reload
la systemctl enable voicestudio.service
# Pas de `--now` : le moteur ne doit pas démarrer sans sa clé d'API. voicestudioctl (start / wake) la pousse
# puis le lance (assurer_moteur).
touch "$SENTINEL"
log "VoiceStudio provisionné sur $LXC_IP:$PORT (le démarrage du moteur revient à voicestudioctl)"
