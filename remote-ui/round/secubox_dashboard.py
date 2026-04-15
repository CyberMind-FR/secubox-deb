#!/usr/bin/env python3
"""
SecuBox Remote UI — Round Dashboard (PIL/Framebuffer RGB565)
Direct framebuffer rendering for HyperPixel 2.1 Round 480x480
No X11 or Chromium needed - lightweight Python/PIL solution

CyberMind — https://cybermind.fr
Author: Gérald Kerma <gandalf@gk2.net>
License: Proprietary / ANSSI CSPN candidate

Requirements:
  - python3-pil
  - HyperPixel 2.1 Round with KMS overlay (vc4-kms-dpi-hyperpixel2r)
  - Framebuffer at /dev/fb0 (RGB565, 480x480)

Usage:
  sudo python3 secubox_dashboard.py &
"""
import os
import math
import time
import struct
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
import subprocess

WIDTH, HEIGHT = 480, 480
CX, CY = 240, 240

MODULES = [
    ('AUTH', '#C04E24', 214),
    ('WALL', '#9A6010', 201),
    ('BOOT', '#803018', 188),
    ('MIND', '#3D35A0', 175),
    ('ROOT', '#0A5840', 162),
    ('MESH', '#104A88', 149),
]

def get_cpu():
    try:
        with open('/proc/stat') as f:
            vals = [int(x) for x in f.readline().split()[1:]]
        idle, total = vals[3], sum(vals)
        if not hasattr(get_cpu, 'last'):
            get_cpu.last = (idle, total)
            return 0
        d_idle = idle - get_cpu.last[0]
        d_total = total - get_cpu.last[1]
        get_cpu.last = (idle, total)
        return 100 * (1 - d_idle / max(d_total, 1))
    except: return 0

def get_mem():
    try:
        with open('/proc/meminfo') as f:
            mem = {l.split()[0].rstrip(':'): int(l.split()[1]) for l in f.readlines()[:5]}
        return 100 * (1 - mem.get('MemAvailable', 0) / mem.get('MemTotal', 1))
    except: return 0

def get_disk():
    try:
        st = os.statvfs('/')
        return 100 * (st.f_blocks - st.f_bfree) / st.f_blocks
    except: return 0

def get_load():
    try: return min(100, os.getloadavg()[0] * 50)
    except: return 0

def get_temp():
    try:
        with open('/sys/class/thermal/thermal_zone0/temp') as f:
            return int(f.read()) / 1000
    except: return 0

def get_wifi():
    try:
        with open('/proc/net/wireless') as f:
            lines = f.readlines()
        if len(lines) > 2:
            return min(100, max(0, float(lines[2].split()[3].rstrip('.')) + 100))
    except: pass
    return 50

def get_uptime():
    try:
        with open('/proc/uptime') as f:
            s = int(float(f.read().split()[0]))
        return f"up {s//3600}h{(s%3600)//60:02d}"
    except: return "up --"

def draw_ring(draw, cx, cy, r, color, pct):
    for a in range(0, 360, 4):
        rad = math.radians(a - 90)
        x, y = cx + r * math.cos(rad), cy + r * math.sin(rad)
        draw.ellipse([x-3, y-3, x+3, y+3], fill='#1a1a1a')
    for a in range(0, int(min(pct, 100) * 3.6), 4):
        rad = math.radians(a - 90)
        x, y = cx + r * math.cos(rad), cy + r * math.sin(rad)
        draw.ellipse([x-4, y-4, x+4, y+4], fill=color)

def rgb_to_rgb565(img):
    """Convert PIL RGB image to RGB565 bytes"""
    data = []
    pixels = img.load()
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = pixels[x, y][:3]
            # RGB565: RRRRRGGG GGGBBBBB
            rgb565 = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            data.append(struct.pack('<H', rgb565))
    return b''.join(data)

def render_frame():
    img = Image.new('RGB', (WIDTH, HEIGHT), '#080808')
    draw = ImageDraw.Draw(img)
    
    metrics = [get_cpu(), get_mem(), get_disk(), get_load(), get_temp() * 1.3, get_wifi()]
    
    for i, (_, color, r) in enumerate(MODULES):
        draw_ring(draw, CX, CY, r, color, metrics[i])
    
    try:
        fb = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf', 28)
        fm = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 16)
        fs = ImageFont.truetype('/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf', 12)
    except:
        fb = fm = fs = ImageFont.load_default()
    
    now = datetime.now()
    hostname = subprocess.getoutput('hostname').strip()
    
    draw.text((CX, CY-35), now.strftime('%H:%M:%S'), fill='#e8e6d9', font=fb, anchor='mm')
    draw.text((CX, CY-8), now.strftime('%a %d %b').lower(), fill='#6b6b7a', font=fm, anchor='mm')
    draw.text((CX, CY+14), hostname, fill='#00d4ff', font=fm, anchor='mm')
    draw.text((CX, CY+34), get_uptime(), fill='#6b6b7a', font=fs, anchor='mm')
    draw.text((CX, 20), 'SECUBOX', fill='#c9a84c', font=fm, anchor='mm')
    draw.text((CX, 45), '● OTG', fill='#0A5840', font=fs, anchor='mm')
    
    status = ('● NOMINAL', '#00ff41') if metrics[0] < 85 and metrics[1] < 90 else ('▲ WARNING', '#e63946')
    draw.text((CX, 420), status[0], fill=status[1], font=fm, anchor='mm')
    
    temp = get_temp()
    draw.rectangle([160, 442, 320, 454], outline='#333', width=1)
    bar_color = '#0A5840' if temp < 65 else '#e63946'
    draw.rectangle([161, 443, 161 + int(158 * min(temp/80, 1)), 453], fill=bar_color)
    draw.text((CX, 465), f'TEMP {int(temp)}C', fill='#6b6b7a', font=fs, anchor='mm')
    
    return img

def main():
    print("SecuBox Dashboard starting (RGB565)...")
    
    try:
        while True:
            img = render_frame()
            rgb565_data = rgb_to_rgb565(img)
            
            with open('/dev/fb0', 'wb') as fb:
                fb.write(rgb565_data)
            
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("Stopped")

if __name__ == '__main__':
    main()
