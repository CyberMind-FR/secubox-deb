# ══════════════════════════════════════════════════════════════════
#  CONFIG HÔTE PROXMOX — Passthrough binder vers LXC ReDroid
#  À appliquer sur le NODE Proxmox (hôte physique)
#  AVANT de lancer le wizard dans le LXC
# ══════════════════════════════════════════════════════════════════

# ── 1. Charger les modules sur l'HÔTE ────────────────────────────
apt install linux-modules-extra-$(uname -r)
modprobe binder_linux devices="binder,hwbinder,vndbinder"
modprobe ashmem_linux

# Persistance au reboot (hôte)
cat >> /etc/modules << 'EOF'
binder_linux
ashmem_linux
EOF

cat >> /etc/modprobe.d/binder.conf << 'EOF'
options binder_linux devices=binder,hwbinder,vndbinder
EOF

# ── 2. Config LXC dans Proxmox (/etc/pve/lxc/<CTID>.conf) ────────
# Remplacer <CTID> par l'ID de ton conteneur (ex: 200)

cat >> /etc/pve/lxc/<CTID>.conf << 'EOF'

# ReDroid — Android container
# Nesting + privileges
features: nesting=1
lxc.apparmor.profile: unconfined

# Binder device passthrough
lxc.cgroup2.devices.allow: c 10:* rwm
lxc.mount.entry: /dev/binder     dev/binder     none bind,optional,create=file 0 0
lxc.mount.entry: /dev/hwbinder   dev/hwbinder   none bind,optional,create=file 0 0
lxc.mount.entry: /dev/vndbinder  dev/vndbinder  none bind,optional,create=file 0 0

# Ashmem (Android 11 et inférieur)
lxc.mount.entry: /dev/ashmem     dev/ashmem     none bind,optional,create=file 0 0
EOF

# ── 3. Redémarrer le LXC ─────────────────────────────────────────
pct stop <CTID> && pct start <CTID>

# ── 4. Vérifier dans le LXC ──────────────────────────────────────
# pct enter <CTID>
# ls -la /dev/binder /dev/hwbinder /dev/vndbinder

# ══════════════════════════════════════════════════════════════════
#  Notes architecture
# ══════════════════════════════════════════════════════════════════
#
#  ESPRESSObin / MOCHAbin (Marvell Armada 3720, ARM64)
#  → Image : redroid/redroid:12.0.0_64only-latest (arm64 tag)
#  → Pas de NDK bridge nécessaire (natif ARM)
#
#  x86_64 host
#  → Image : redroid/redroid:12.0.0_64only-latest (amd64 tag)
#  → NDK bridge libndk_translation activé pour apps ARM
#
# ══════════════════════════════════════════════════════════════════
