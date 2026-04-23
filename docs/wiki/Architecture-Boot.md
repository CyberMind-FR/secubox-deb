# Boot Architecture

**SecuBox-DEB** uses a five-layer boot chain from hardware firmware to user space. Three exclusive execution modes are available: maintenance (`PROMPT`), display (`KIOSK`), or production (`API`).

---

## Boot Chain Overview

### Layer 1 — HW / BootLoader

| Platform | Firmware | Notes |
|----------|----------|-------|
| Lenovo ThinkCentre M710q | BIOS/UEFI | x86_64, Secure Boot capable |
| MOCHAbin (Armada 7040) | U-Boot | ARM64, eMMC or NVMe boot |
| ESPRESSObin (Armada 3720) | U-Boot | ARM64, SD or eMMC boot |

### Layer 2 — OS / UEFI (GRUB2)

GRUB2 handles kernel selection, signature verification (Secure Boot), and optional TPM2 unsealing (`tpm2_unseal`).

**CSPN Compliance Points:**
- `/boot` partition is unencrypted (FAT32/ext4) but protected by UEFI signature verification
- Kernel command line parameters are locked in production
- GRUB password is mandatory on production targets

### Layer 3 — Kernel + InitRamfs

#### Hardened Linux Kernel

```
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_SHA512=y
CONFIG_HARDENED_USERCOPY=y
CONFIG_RANDOMIZE_BASE=y   # KASLR
```

Built-in modules: `nftables`, `WireGuard`, `eBPF` (restricted), MOCHAbin network drivers (mvneta/mvpp2).

#### InitRamfs Operations

1. Mount encrypted LUKS2 disk (`cryptsetup luksOpen`)
2. Verify ZKP pre-mount proof (GK·HAM-HASH L1)
3. Mount encrypted root on `/sysroot`
4. `switch_root` to Rootfs

### Layer 4 — Rootfs / INIT (systemd)

After `pivot_root`, systemd orchestrates the 10-phase SecuBox-DEB startup:

| Phase | Services | SecuBox Pairs |
|-------|----------|---------------|
| 1 — Network | nftables, WireGuard, Tailscale | MESH↔AUTH |
| 2 — Perimeter Security | CrowdSec, HAProxy | WALL↔MIND |
| 3 — DPI dual-stream | nDPId (active/shadow) | WALL↔MIND |
| 4 — Runtime API | FastAPI/Uvicorn, 4R buffer | BOOT↔ROOT |
| 5 — ZKP auth | GK·HAM-HASH (L1/L2/L3) | BOOT↔ROOT |
| 6 — MirrorNet P2P | WireGuard + did:plc | MESH↔AUTH |
| 7 — Notarization | ALERTE·DÉPÔT blind notarization | WALL↔MIND |
| 8 — Display | HyperPixel / RPi Zero coprocessor | MESH↔AUTH |
| 9 — Monitoring | Metrics, alerts, SIEM | WALL↔MIND |
| 10 — Finalization | Health-check, seal TPM2 | BOOT↔ROOT |

---

## Execution Modes

### PROMPT `<LOG>` — Maintenance Mode

**Target:** `secubox-prompt.target`

- Shell access via physical console or restricted SSH
- Full audit logging (`auditd` + `systemd-journal`, 90-day retention)
- Production services (API, DPI, MirrorNet) are stopped

```bash
echo "MODE=PROMPT" > /etc/secubox/runtime.conf
systemctl isolate secubox-prompt.target
```

### KIOSK `[UI]` — Display Mode

**Target:** `secubox-kiosk.target`

- Locked UI for metrics display on HyperPixel
- No shell access, no inbound network interfaces
- Communication via Unix socket (read-only)
- Auto-restart on crash

```bash
echo "MODE=KIOSK" > /etc/secubox/runtime.conf
systemctl isolate secubox-kiosk.target
```

### API `(RT)` — Production Mode

**Target:** `secubox-api.target` (default)

- FastAPI/Uvicorn on Unix socket (HAProxy TLS frontend)
- 4R double-buffer active on L2
- nDPId dual-stream listening
- CrowdSec in agent mode
- No interactive shell, no external SSH

```bash
echo "MODE=API" > /etc/secubox/runtime.conf
systemctl isolate secubox-api.target
```

---

## Module Color Correspondence

| Color | Hex | Layer / Mode |
|-------|-----|--------------|
| BOOT | `#803018` | HW / BootLoader |
| WALL | `#9A6010` | OS / UEFI |
| MIND | `#3D35A0` | Kernel + InitRamfs |
| ROOT | `#0A5840` | Rootfs / INIT — API Mode |
| MESH | `#104A88` | KIOSK Mode [UI] |
| AUTH | `#C04E24` | PROMPT Mode \<LOG\> |

---

## CSPN Control Points

- [ ] Kernel and module signatures verified by Secure Boot
- [ ] InitRD without plaintext secrets (`lsinitrd | grep -i key`)
- [ ] TPM2 sealing to PCR 0+7+14 validated after kernel updates
- [ ] PROMPT mode only accessible via physical console or certificate SSH
- [ ] Audit logs exported and signed before each PROMPT session
- [ ] API mode won't start if ZKP L1 proof fails
- [ ] Network isolation between modes verified by `nft list ruleset`

---

## Bootstrap Device (Eye Remote v2.1+)

The Eye Remote can function as a **boot device** for MOCHAbin and ESPRESSObin systems:

- **Mass Storage LUN** — U-Boot loads kernel/DTB/initrd from active slot
- **TFTP Shadow** — Test new images before atomic promotion
- **Safe Recovery** — Fallback boot when internal storage is corrupted
- **A/B Slot Management** — Automatic rollback on boot failure

See [[Eye-Remote-Bootstrap]] for full implementation details.

---

*See also: [[Architecture-Security]], [[Architecture-Modules]], [[Eye-Remote-Bootstrap]]*
