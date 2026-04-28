#!/usr/bin/env python3
"""
SecuBox Eye Remote - Test Touch I2C
Script de test pour verifier la connexion au controleur tactile HyperPixel 2r.

Usage:
    python3 test_touch_i2c.py

Prerequis:
    - pip install hyperpixel2r
    - dtoverlay=hyperpixel2r:disable-touch dans /boot/config.txt
    - Reboot apres modification de config.txt

CyberMind - https://cybermind.fr
"""

import sys
import time

# Configuration HyperPixel 2r
I2C_BUS = 11
I2C_ADDR = 0x15
INT_PIN = 27


def test_i2c_direct():
    """Test acces I2C direct via smbus2."""
    print("=" * 60)
    print("Test 1: Acces I2C direct (smbus2)")
    print("=" * 60)

    try:
        import smbus2
    except ImportError:
        print("[FAIL] smbus2 non installe: pip install smbus2")
        return False

    try:
        bus = smbus2.SMBus(I2C_BUS)
        print(f"[OK] Bus I2C {I2C_BUS} ouvert")

        # Try to read a byte from the touch controller
        try:
            data = bus.read_byte(I2C_ADDR)
            print(f"[OK] Lecture adresse 0x{I2C_ADDR:02X}: 0x{data:02X}")
            bus.close()
            return True
        except OSError as e:
            print(f"[FAIL] Erreur lecture 0x{I2C_ADDR:02X}: {e}")
            bus.close()
            return False

    except FileNotFoundError:
        print(f"[FAIL] Bus I2C {I2C_BUS} non trouve")
        print("       Le HyperPixel cree le bus 11 via son overlay")
        print("       Verifiez: dtoverlay=hyperpixel2r dans /boot/config.txt")
        return False
    except PermissionError:
        print(f"[FAIL] Permission refusee sur /dev/i2c-{I2C_BUS}")
        print("       Ajoutez l'utilisateur au groupe i2c ou utilisez sudo")
        return False


def test_i2c_scan():
    """Scanner tous les bus I2C disponibles."""
    print("\n" + "=" * 60)
    print("Test 2: Scan des bus I2C disponibles")
    print("=" * 60)

    try:
        import smbus2
    except ImportError:
        print("[SKIP] smbus2 requis")
        return

    import os

    found_buses = []
    for i in range(20):
        if os.path.exists(f"/dev/i2c-{i}"):
            found_buses.append(i)

    if not found_buses:
        print("[WARN] Aucun bus I2C trouve")
        return

    print(f"Bus I2C disponibles: {found_buses}")

    for bus_num in found_buses:
        print(f"\n--- Bus {bus_num} ---")
        try:
            bus = smbus2.SMBus(bus_num)
            devices = []
            for addr in range(0x03, 0x78):
                try:
                    bus.read_byte(addr)
                    devices.append(f"0x{addr:02X}")
                except OSError:
                    pass
            bus.close()

            if devices:
                print(f"  Peripheriques: {', '.join(devices)}")
                if "0x15" in devices:
                    print(f"  [!!!] Touch controller trouve sur bus {bus_num}!")
            else:
                print("  Aucun peripherique")
        except Exception as e:
            print(f"  Erreur: {e}")


def test_hyperpixel2r_lib():
    """Test avec la bibliotheque Pimoroni hyperpixel2r."""
    print("\n" + "=" * 60)
    print("Test 3: Bibliotheque Pimoroni hyperpixel2r")
    print("=" * 60)

    try:
        from hyperpixel2r import Touch
    except ImportError:
        print("[FAIL] hyperpixel2r non installe: pip install hyperpixel2r")
        return False

    print("[OK] Module hyperpixel2r importe")

    try:
        touch = Touch(
            bus=I2C_BUS,
            i2c_addr=I2C_ADDR,
            interrupt_pin=INT_PIN
        )
        print(f"[OK] Touch controller initialise (bus={I2C_BUS}, addr=0x{I2C_ADDR:02X})")

        # Register callback
        touches_received = []

        @touch.on_touch
        def handle_touch(touch_id, x, y, state):
            action = "PRESS" if state else "RELEASE"
            print(f"  Touch {touch_id}: ({x}, {y}) {action}")
            touches_received.append((touch_id, x, y, state))

        print("\n[INFO] Touchez l'ecran pendant 5 secondes...")
        time.sleep(5)

        if touches_received:
            print(f"\n[OK] {len(touches_received)} evenements recus!")
            return True
        else:
            print("\n[WARN] Aucun evenement recu")
            print("       Verifiez que :disable-touch est dans l'overlay")
            return False

    except Exception as e:
        print(f"[FAIL] Erreur initialisation: {e}")
        return False


def test_evdev():
    """Test avec evdev (fallback kernel)."""
    print("\n" + "=" * 60)
    print("Test 4: Evdev (pilote kernel)")
    print("=" * 60)

    try:
        import evdev
    except ImportError:
        print("[FAIL] evdev non installe: pip install evdev")
        return False

    print("[OK] Module evdev importe")

    from pathlib import Path
    touch_devices = []

    for event_path in sorted(Path("/dev/input").glob("event*")):
        try:
            device = evdev.InputDevice(str(event_path))
            caps = device.capabilities()

            if evdev.ecodes.EV_ABS in caps:
                abs_caps = dict(caps[evdev.ecodes.EV_ABS])
                if evdev.ecodes.ABS_MT_SLOT in abs_caps:
                    touch_devices.append((event_path, device.name))
                    print(f"  [FOUND] {event_path}: {device.name}")

            device.close()
        except (OSError, PermissionError) as e:
            print(f"  [SKIP] {event_path}: {e}")

    if touch_devices:
        print(f"\n[OK] {len(touch_devices)} peripherique(s) tactile(s) trouve(s)")

        # Check if HyperPixel is claimed by kernel
        hp_found = any('hyperpixel' in name.lower() or 'goodix' in name.lower()
                       or 'ft5' in name.lower()
                       for _, name in touch_devices)

        if hp_found:
            print("[INFO] HyperPixel touch gere par le kernel")
            print("       Pour utiliser hyperpixel2r Python, ajoutez:")
            print("       dtoverlay=hyperpixel2r:disable-touch")
        return True
    else:
        print("\n[WARN] Aucun peripherique tactile evdev")
        return False


def check_config_txt():
    """Verifier la configuration dans /boot/config.txt."""
    print("\n" + "=" * 60)
    print("Test 5: Configuration /boot/config.txt")
    print("=" * 60)

    config_paths = [
        "/boot/config.txt",
        "/boot/firmware/config.txt"
    ]

    config_content = None
    config_path = None

    for path in config_paths:
        try:
            with open(path, 'r') as f:
                config_content = f.read()
                config_path = path
                break
        except FileNotFoundError:
            continue

    if not config_content:
        print("[WARN] config.txt non trouve")
        return

    print(f"[OK] Lecture de {config_path}")

    # Check for HyperPixel overlay
    if "hyperpixel2r" in config_content:
        print("[OK] dtoverlay=hyperpixel2r present")

        if ":disable-touch" in config_content:
            print("[OK] :disable-touch active")
            print("     -> Utiliser hyperpixel2r Python library")
        else:
            print("[WARN] :disable-touch absent")
            print("       Le kernel gere le touch via evdev")
            print("       Pour Python direct, modifier en:")
            print("       dtoverlay=hyperpixel2r:disable-touch")
    else:
        print("[FAIL] dtoverlay=hyperpixel2r absent!")
        print("       Ajoutez dans config.txt:")
        print("       dtoverlay=hyperpixel2r")

    # Check I2C
    if "dtparam=i2c_arm=on" in config_content or "i2c_arm=on" in config_content:
        print("[OK] I2C active")
    else:
        print("[WARN] I2C peut-etre desactive")


def main():
    """Executer tous les tests."""
    print("\n" + "#" * 60)
    print("# SecuBox Eye Remote - Test Touch I2C")
    print("# HyperPixel 2r Touch Controller Diagnostic")
    print("#" * 60)

    check_config_txt()
    test_i2c_scan()
    i2c_ok = test_i2c_direct()
    evdev_ok = test_evdev()
    hp_ok = test_hyperpixel2r_lib()

    print("\n" + "=" * 60)
    print("RESUME")
    print("=" * 60)
    print(f"  I2C direct (bus {I2C_BUS}, addr 0x{I2C_ADDR:02X}): {'OK' if i2c_ok else 'FAIL'}")
    print(f"  Evdev (kernel driver): {'OK' if evdev_ok else 'FAIL'}")
    print(f"  Pimoroni hyperpixel2r: {'OK' if hp_ok else 'FAIL'}")

    print("\nRECOMMANDATION:")
    if hp_ok:
        print("  Utiliser touch_handler.py avec hyperpixel2r (mode actuel)")
    elif evdev_ok:
        print("  Le kernel gere le touch - evdev fonctionne")
        print("  Pour hyperpixel2r Python, ajouter :disable-touch")
    else:
        print("  Verifier le cablage et la configuration HyperPixel")

    return 0 if (hp_ok or evdev_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
