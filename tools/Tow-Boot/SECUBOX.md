# Tow-Boot for SecuBox-DEB

Custom Tow-Boot build with eMMC boot partition support for GlobalScale MOCHAbin.

## Changes from Upstream

### eMMC Boot Support (`CONFIG_SUPPORT_EMMC_BOOT=y`)

Added `mmcBootIndex = "0"` to MOCHAbin board configs to enable:
- `mmc partconf` command
- `mmc bootbus` command
- eMMC boot partition access

Modified files:
- `boards/globalscale-mochabin-2gb/default.nix`
- `boards/globalscale-mochabin-4gb/default.nix`
- `boards/globalscale-mochabin-8gb/default.nix`

## Building

Requires Nix package manager:

```bash
# Add user to nix-users group (one-time)
sudo usermod -aG nix-users $USER

# Build (use sg if not logged out/in)
sg nix-users -c "nix-build -A globalscale-mochabin-8gb"

# Or for other RAM variants:
sg nix-users -c "nix-build -A globalscale-mochabin-4gb"
sg nix-users -c "nix-build -A globalscale-mochabin-2gb"
```

## Output Files

After build, binaries are in `output/` (copied from Nix store):

| File | Purpose |
|------|---------|
| `Tow-Boot.spi.bin` | SPI NOR flash boot |
| `Tow-Boot.mmcboot.bin` | eMMC boot partition |
| `Tow-Boot.noenv.bin` | No environment storage |

## Flashing

### SPI Flash (Primary)

```
sf probe
sf erase 0 0x400000
sf write $loadaddr 0 $filesize
```

### eMMC Boot Partition (If SPI Dead)

```
mmc dev 0 1
mmc write $loadaddr 0 0xb80
mmc bootbus 0 1 0 0
mmc partconf 0 1 1 0
```

### UART Recovery

```bash
sudo mvebu64boot -t -b output/Tow-Boot.spi.bin /dev/ttyUSB0
# Then power cycle the board
```

## Boot Mode Jumpers (J17-J22)

| Mode | Code | J17 | J18 | J19 | J20 | J21 | J22 |
|------|------|-----|-----|-----|-----|-----|-----|
| SPI | 0x32 | L | R | L | L | R | R |
| eMMC | 0x2B | R | R | L | R | L | R |

L = Left (pins 2-3), R = Right (pins 1-2)

## Version

Based on Tow-Boot 2022.07-009-pre with SecuBox modifications.

## Upstream

- https://tow-boot.org/
- https://github.com/Tow-Boot/Tow-Boot
