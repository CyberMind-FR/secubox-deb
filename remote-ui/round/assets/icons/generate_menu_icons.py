#!/usr/bin/env python3
"""Generate placeholder menu icons."""
from PIL import Image, ImageDraw

ICONS = [
    ("devices", "#C04E24"),
    ("secubox", "#9A6010"),
    ("local", "#803018"),
    ("network", "#3D35A0"),
    ("security", "#0A5840"),
    ("exit", "#104A88"),
    ("back", "#6b6b7a"),
    ("scan", "#C04E24"),
    ("plus", "#0A5840"),
    ("trash", "#C04E24"),
    ("refresh", "#104A88"),
    ("status", "#0A5840"),
    ("modules", "#3D35A0"),
    ("logs", "#6b6b7a"),
    ("restart", "#9A6010"),
    ("update", "#104A88"),
    ("display", "#c9a84c"),
    ("system", "#3D35A0"),
    ("info", "#104A88"),
    ("brightness", "#c9a84c"),
    ("theme", "#3D35A0"),
    ("timeout", "#6b6b7a"),
    ("rotate", "#9A6010"),
    ("test", "#0A5840"),
    ("usb", "#C04E24"),
    ("wifi", "#104A88"),
    ("hostname", "#6b6b7a"),
    ("dns", "#3D35A0"),
    ("interfaces", "#104A88"),
    ("routes", "#0A5840"),
    ("traffic", "#9A6010"),
    ("alert", "#C04E24"),
    ("ban", "#C04E24"),
    ("rules", "#3D35A0"),
    ("audit", "#6b6b7a"),
    ("lock", "#C04E24"),
    ("dashboard", "#c9a84c"),
    ("sleep", "#3D35A0"),
    ("reboot", "#9A6010"),
    ("shutdown", "#C04E24"),
    ("cpu", "#C04E24"),
    ("memory", "#9A6010"),
    ("disk", "#803018"),
    ("temp", "#C04E24"),
    ("clock", "#104A88"),
]

SIZES = [22, 48]

for name, color in ICONS:
    for size in SIZES:
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Simple circle with first letter
        margin = size // 8
        draw.ellipse(
            [margin, margin, size - margin, size - margin],
            fill=color
        )

        # Letter
        letter = name[0].upper()
        text_size = size // 2
        draw.text(
            (size // 2 - text_size // 4, size // 2 - text_size // 2),
            letter,
            fill="#e8e6d9"
        )

        img.save(f"{name}-{size}.png")
        print(f"Created {name}-{size}.png")

print("Done!")
