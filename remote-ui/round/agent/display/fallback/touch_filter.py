#!/usr/bin/env python3
"""
X-Stable Pattern Filter.

Noise pattern: X stable (delta ~0), Y oscillates
Real touch: X changes OR stable X+Y together

Filter: Reject when X delta is near-zero but Y delta is large
"""
import time
import smbus2
import struct
from collections import deque
from PIL import Image, ImageDraw

WIDTH = HEIGHT = 480
CENTER = 240
I2C_BUS = 11
I2C_ADDR = 0x15

# Pattern detection
HISTORY_SIZE = 8
X_STABLE_THRESHOLD = 5      # X delta < 5 = stable
Y_OSCILLATE_THRESHOLD = 15  # Y delta > 15 = oscillating
PATTERN_MATCH_COUNT = 4     # Need 4/8 matching noise pattern to reject

# Touch confirmation
REAL_TOUCH_STREAK = 3       # Need 3 consecutive non-noise readings
DEBOUNCE = 0.1

class PatternFilter:
    def __init__(self):
        self.x_history = deque(maxlen=HISTORY_SIZE)
        self.y_history = deque(maxlen=HISTORY_SIZE)
        self.last_x = None
        self.last_y = None
        self.real_streak = 0
        self.state = 'WAIT'
        self.last_confirm = 0
        self.touch_pos = None

    def update(self, x, y):
        now = time.time()

        if self.last_x is not None:
            dx = abs(x - self.last_x)
            dy = abs(y - self.last_y)

            # Is this reading matching noise pattern? (X stable, Y moving)
            is_noise_pattern = (dx < X_STABLE_THRESHOLD and dy > Y_OSCILLATE_THRESHOLD)

            self.x_history.append(dx)
            self.y_history.append(dy)

            # Count how many recent readings match noise pattern
            noise_matches = 0
            if len(self.x_history) >= 4:
                for i in range(len(self.x_history)):
                    if self.x_history[i] < X_STABLE_THRESHOLD and self.y_history[i] > Y_OSCILLATE_THRESHOLD:
                        noise_matches += 1

            # Decision
            if noise_matches >= PATTERN_MATCH_COUNT:
                # Noise pattern detected
                self.real_streak = 0
                self.state = 'NOISE'
                if self.touch_pos:
                    print(f"RELEASE (noise): {self.touch_pos}")
                    self.touch_pos = None
            else:
                # Not matching noise pattern - could be real
                self.real_streak += 1

                if self.real_streak >= REAL_TOUCH_STREAK:
                    if self.state != 'TOUCH' and now - self.last_confirm > DEBOUNCE:
                        self.state = 'TOUCH'
                        self.touch_pos = (x, y)
                        self.last_confirm = now
                        print(f"TOUCH: ({x}, {y})")
                else:
                    self.state = 'BUILD'

        self.last_x, self.last_y = x, y
        return self.state, self.real_streak, len(self.x_history)

def draw_frame(x=None, y=None, state='WAIT', streak=0, history_len=0, dx=0, dy=0):
    img = Image.new('RGB', (WIDTH, HEIGHT), (10, 10, 20))
    draw = ImageDraw.Draw(img)

    # Grid
    draw.line([(0, CENTER), (WIDTH, CENTER)], fill=(30, 30, 45))
    draw.line([(CENTER, 0), (CENTER, HEIGHT)], fill=(30, 30, 45))
    for r in [60, 120, 180, 220]:
        draw.ellipse([CENTER-r, CENTER-r, CENTER+r, CENTER+r], outline=(25, 25, 40))

    # Pattern indicator - show if current reading matches noise pattern
    is_noise_pat = (dx < X_STABLE_THRESHOLD and dy > Y_OSCILLATE_THRESHOLD)

    colors = {
        'WAIT':  (60, 60, 80),
        'NOISE': (150, 40, 40),
        'BUILD': (200, 180, 0),
        'TOUCH': (0, 255, 100),
    }
    color = colors.get(state, (100, 100, 100))

    if x is not None:
        if state == 'TOUCH':
            draw.ellipse([x-35, y-35, x+35, y+35], outline=color, width=5)
            draw.ellipse([x-8, y-8, x+8, y+8], fill=color)
        elif state == 'BUILD':
            size = 12 + streak * 5
            draw.ellipse([x-size, y-size, x+size, y+size], outline=color, width=3)
        elif state == 'NOISE':
            draw.ellipse([x-4, y-4, x+4, y+4], fill=color)
        else:
            draw.ellipse([x-6, y-6, x+6, y+6], outline=color, width=2)

    # Status
    draw.text((10, 10), f"[{state}]", fill=color)
    draw.text((10, 30), f"streak: {streak}/{REAL_TOUCH_STREAK}", fill=(120, 120, 140))
    draw.text((10, 50), f"dX={dx} dY={dy}", fill=(100, 100, 120))

    # Pattern match indicator
    pat_color = (150, 40, 40) if is_noise_pat else (40, 150, 40)
    pat_text = "NOISE PATTERN" if is_noise_pat else "OK pattern"
    draw.text((10, 70), pat_text, fill=pat_color)

    # Legend
    draw.text((300, 10), "X-STABLE FILTER", fill=(100, 150, 200))
    draw.text((300, 30), f"Noise: dX<{X_STABLE_THRESHOLD} & dY>{Y_OSCILLATE_THRESHOLD}", fill=(80, 80, 100))

    # Streak bar
    if REAL_TOUCH_STREAK > 0:
        pct = min(1.0, streak / REAL_TOUCH_STREAK)
        bar_color = (0, 200, 100) if streak >= REAL_TOUCH_STREAK else (200, 200, 0)
        draw.rectangle([140, 455, 140 + int(pct * 200), 465], fill=bar_color)
        draw.rectangle([140, 455, 340, 465], outline=(50, 50, 70))

    rgba = img.convert('RGBA')
    with open('/dev/fb0', 'wb') as fb:
        fb.write(rgba.tobytes('raw', 'BGRA'))

def main():
    print("X-Stable Pattern Filter")
    print(f"Noise = dX < {X_STABLE_THRESHOLD} AND dY > {Y_OSCILLATE_THRESHOLD}")

    bus = smbus2.SMBus(I2C_BUS)
    filt = PatternFilter()
    last_x, last_y = None, None

    draw_frame()

    try:
        while True:
            try:
                count = bus.read_byte_data(I2C_ADDR, 0x02)

                if count > 0:
                    data = bus.read_i2c_block_data(I2C_ADDR, 0x03, 6)
                    data[0] &= 0x0f
                    data[2] &= 0x0f
                    tx, ty, p1, p2 = struct.unpack(">HHBB", bytes(data))

                    # Calculate deltas for display
                    dx = abs(tx - last_x) if last_x else 0
                    dy = abs(ty - last_y) if last_y else 0

                    state, streak, hist_len = filt.update(tx, ty)
                    draw_frame(tx, ty, state, streak, hist_len, dx, dy)

                    last_x, last_y = tx, ty

            except Exception as e:
                if "Remote I/O error" not in str(e):
                    print(f"Err: {e}")

            time.sleep(0.025)

    except KeyboardInterrupt:
        pass
    finally:
        bus.close()

if __name__ == "__main__":
    main()
