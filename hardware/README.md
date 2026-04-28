# SecuBox Hardware

Hardware designs and documentation for SecuBox peripherals.

## Contents

| Directory | Description |
|-----------|-------------|
| `smart-strip/` | SecuBox Smart-Strip v1.1 - USB-C powered PDU with I²C control |

## Smart-Strip

4-outlet smart power strip with:
- USB-C PD input (up to 100W)
- Individual relay control per outlet
- I²C secondary interface (JST-SH Qwiic compatible)
- Default I²C address: `0x42`

**Fritzing part**: `smart-strip/secubox-smart-strip.fzpz`

See `smart-strip/README.md` for wiring examples (RPi, ESP32, Arduino).

## PCB Manufacturing

Production PCBs are designed in KiCad (4-layer USB HS controlled-impedance).
Fritzing files are for documentation and community sketches only.

---

*CyberMind / SecuBox Hardware*
