#!/usr/bin/env python3
"""
Noise Pattern Analyzer.

Question: Is noise repetitive SAME coordinates? Or SAME differences?
This will tell us if it's:
- Same coords repeating → hardware stuck / calibration issue
- Same differences → interference pattern / EMI
- Random → true noise
"""
import time
import smbus2
import struct
from collections import Counter, deque
from PIL import Image, ImageDraw

WIDTH = HEIGHT = 480
I2C_BUS = 11
I2C_ADDR = 0x15

# Track patterns
coord_history = []        # All (x, y) pairs
delta_history = []        # All (dx, dy) deltas between consecutive reads
last_x, last_y = None, None

def draw_analysis(coords, deltas, elapsed):
    img = Image.new('RGB', (WIDTH, HEIGHT), (10, 10, 20))
    draw = ImageDraw.Draw(img)

    # Stats
    draw.text((10, 10), f"NOISE PATTERN ANALYSIS", fill=(200, 200, 100))
    draw.text((10, 30), f"Samples: {len(coords)} in {elapsed:.1f}s", fill=(120, 120, 140))

    if len(coords) >= 10:
        # Coordinate frequency analysis
        coord_counts = Counter(coords)
        most_common = coord_counts.most_common(5)

        draw.text((10, 60), "TOP 5 REPEATED COORDS:", fill=(100, 180, 255))
        y_pos = 80
        for i, ((x, y), count) in enumerate(most_common):
            pct = count / len(coords) * 100
            draw.text((20, y_pos), f"{i+1}. ({x}, {y}) × {count} = {pct:.1f}%",
                     fill=(150, 150, 180))
            y_pos += 18

        # Are coords repeating exactly?
        unique_coords = len(coord_counts)
        draw.text((10, 180), f"Unique coords: {unique_coords} / {len(coords)}",
                 fill=(200, 200, 100))

        if unique_coords < len(coords) * 0.3:
            draw.text((10, 200), "→ SAME COORDS REPEATING!", fill=(255, 100, 100))
        elif unique_coords < len(coords) * 0.7:
            draw.text((10, 200), "→ SOME coords repeat", fill=(255, 200, 100))
        else:
            draw.text((10, 200), "→ Mostly UNIQUE coords", fill=(100, 255, 100))

    if len(deltas) >= 10:
        # Delta analysis
        delta_counts = Counter(deltas)
        most_common_d = delta_counts.most_common(5)

        draw.text((10, 240), "TOP 5 REPEATED DELTAS (dx,dy):", fill=(100, 255, 180))
        y_pos = 260
        for i, ((dx, dy), count) in enumerate(most_common_d):
            pct = count / len(deltas) * 100
            draw.text((20, y_pos), f"{i+1}. Δ({dx:+d}, {dy:+d}) × {count} = {pct:.1f}%",
                     fill=(150, 150, 180))
            y_pos += 18

        # Are deltas repeating?
        unique_deltas = len(delta_counts)
        draw.text((10, 360), f"Unique deltas: {unique_deltas} / {len(deltas)}",
                 fill=(200, 200, 100))

        if unique_deltas < len(deltas) * 0.3:
            draw.text((10, 380), "→ SAME DIFFERENCES pattern!", fill=(255, 100, 255))
        elif unique_deltas < len(deltas) * 0.7:
            draw.text((10, 380), "→ SOME deltas repeat", fill=(255, 200, 100))
        else:
            draw.text((10, 380), "→ RANDOM differences", fill=(100, 255, 100))

    # X and Y range
    if coords:
        xs = [c[0] for c in coords]
        ys = [c[1] for c in coords]
        draw.text((10, 420), f"X range: {min(xs)}-{max(xs)} (span {max(xs)-min(xs)})",
                 fill=(150, 150, 180))
        draw.text((10, 440), f"Y range: {min(ys)}-{max(ys)} (span {max(ys)-min(ys)})",
                 fill=(150, 150, 180))

    # Verdict
    draw.text((10, 465), "DON'T TOUCH - analyzing ambient noise", fill=(255, 255, 100))

    rgba = img.convert('RGBA')
    with open('/dev/fb0', 'wb') as fb:
        fb.write(rgba.tobytes('raw', 'BGRA'))

def main():
    global last_x, last_y
    print("Noise Pattern Analyzer - DON'T TOUCH THE SCREEN")
    print("Collecting 10 seconds of ambient noise data...")

    bus = smbus2.SMBus(I2C_BUS)
    start_time = time.time()

    draw_analysis([], [], 0)

    try:
        while time.time() - start_time < 30:  # 30 seconds
            try:
                count = bus.read_byte_data(I2C_ADDR, 0x02)

                if count > 0:
                    data = bus.read_i2c_block_data(I2C_ADDR, 0x03, 6)
                    data[0] &= 0x0f
                    data[2] &= 0x0f
                    tx, ty, p1, p2 = struct.unpack(">HHBB", bytes(data))

                    coord_history.append((tx, ty))

                    if last_x is not None:
                        dx = tx - last_x
                        dy = ty - last_y
                        delta_history.append((dx, dy))

                    last_x, last_y = tx, ty

                    elapsed = time.time() - start_time
                    if len(coord_history) % 20 == 0:  # Update display every 20 samples
                        draw_analysis(coord_history, delta_history, elapsed)
                        print(f"Samples: {len(coord_history)}, last: ({tx}, {ty})")

            except Exception as e:
                if "Remote I/O error" not in str(e):
                    print(f"Err: {e}")

            time.sleep(0.025)

    except KeyboardInterrupt:
        pass
    finally:
        bus.close()

        # Final analysis
        print("\n=== FINAL ANALYSIS ===")
        print(f"Total samples: {len(coord_history)}")

        if coord_history:
            coord_counts = Counter(coord_history)
            print(f"\nUnique coordinates: {len(coord_counts)}")
            print("Most repeated coords:")
            for (x, y), count in coord_counts.most_common(10):
                print(f"  ({x}, {y}) appeared {count} times ({count/len(coord_history)*100:.1f}%)")

        if delta_history:
            delta_counts = Counter(delta_history)
            print(f"\nUnique deltas: {len(delta_counts)}")
            print("Most repeated deltas:")
            for (dx, dy), count in delta_counts.most_common(10):
                print(f"  Δ({dx:+d}, {dy:+d}) appeared {count} times ({count/len(delta_history)*100:.1f}%)")

if __name__ == "__main__":
    main()
