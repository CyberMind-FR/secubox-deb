#!/usr/bin/env python3
"""
Touch calibration test.
Shows raw touch coordinates and draws at that position.
Tap corners to verify mapping is correct.
"""
import time
import smbus2
import struct
from PIL import Image, ImageDraw, ImageFont

WIDTH = HEIGHT = 480
I2C_BUS = 11
I2C_ADDR = 0x15

# Target points for calibration
TARGETS = [
    (60, 60, "TOP-LEFT"),
    (420, 60, "TOP-RIGHT"),
    (60, 420, "BOT-LEFT"),
    (420, 420, "BOT-RIGHT"),
    (240, 240, "CENTER"),
]

def draw_frame(touch_x=None, touch_y=None, raw_data=None):
    img = Image.new('RGB', (WIDTH, HEIGHT), (10, 10, 20))
    draw = ImageDraw.Draw(img)

    # Draw target points
    for tx, ty, label in TARGETS:
        draw.ellipse([tx-15, ty-15, tx+15, ty+15], outline=(60, 60, 100), width=2)
        draw.line([(tx-20, ty), (tx+20, ty)], fill=(60, 60, 100))
        draw.line([(tx, ty-20), (tx, ty+20)], fill=(60, 60, 100))
        draw.text((tx-30, ty+20), label, fill=(50, 50, 80))

    # Draw crosshairs
    draw.line([(0, 240), (480, 240)], fill=(30, 30, 50))
    draw.line([(240, 0), (240, 480)], fill=(30, 30, 50))

    # Draw touch point
    if touch_x is not None:
        # Big green crosshair at touch position
        draw.line([(touch_x, 0), (touch_x, 480)], fill=(0, 150, 0), width=1)
        draw.line([(0, touch_y), (480, touch_y)], fill=(0, 150, 0), width=1)
        draw.ellipse([touch_x-25, touch_y-25, touch_x+25, touch_y+25],
                     outline=(0, 255, 100), width=3)
        draw.ellipse([touch_x-5, touch_y-5, touch_x+5, touch_y+5],
                     fill=(0, 255, 100))

        # Show coordinates
        draw.rectangle([5, 5, 200, 80], fill=(20, 20, 30))
        draw.text((10, 10), f"TOUCH X: {touch_x}", fill=(0, 255, 100))
        draw.text((10, 30), f"TOUCH Y: {touch_y}", fill=(0, 255, 100))

        if raw_data:
            draw.text((10, 50), f"RAW: {raw_data[:6]}", fill=(100, 100, 120))

    else:
        draw.text((10, 10), "TAP each target to verify mapping", fill=(100, 150, 200))
        draw.text((10, 30), "Green dot should appear ON target", fill=(80, 80, 120))

    # Axis labels
    draw.text((5, 235), "X=0", fill=(80, 80, 100))
    draw.text((450, 235), "X=480", fill=(80, 80, 100))
    draw.text((245, 5), "Y=0", fill=(80, 80, 100))
    draw.text((245, 460), "Y=480", fill=(80, 80, 100))

    rgba = img.convert('RGBA')
    with open('/dev/fb0', 'wb') as fb:
        fb.write(rgba.tobytes('raw', 'BGRA'))

def main():
    print("Touch Calibration Test")
    print("Tap each corner target - green dot should appear ON target")
    bus = smbus2.SMBus(I2C_BUS)

    draw_frame()
    last_x, last_y = None, None

    try:
        while True:
            try:
                count = bus.read_byte_data(I2C_ADDR, 0x02)

                if count > 0:
                    data = bus.read_i2c_block_data(I2C_ADDR, 0x03, 6)
                    raw = list(data)

                    data[0] &= 0x0f
                    data[2] &= 0x0f
                    tx, ty, p1, p2 = struct.unpack(">HHBB", bytes(data))

                    # Only update if position changed significantly
                    if last_x is None or abs(tx - last_x) > 10 or abs(ty - last_y) > 10:
                        print(f"Touch: ({tx}, {ty}) raw={raw}")
                        draw_frame(tx, ty, raw)
                        last_x, last_y = tx, ty

            except Exception as e:
                if "Remote I/O error" not in str(e):
                    print(f"Err: {e}")

            time.sleep(0.03)

    except KeyboardInterrupt:
        pass
    finally:
        bus.close()

if __name__ == "__main__":
    main()
