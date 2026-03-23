#!/usr/bin/env python3
"""
Apply CRT P31 Phosphor theme to all SecuBox module UIs
"""

import os
import re
import glob

# CRT CSS variables to inject
CRT_ROOT_VARS = """:root {
            /* P31 Phosphor spectrum */
            --p31-peak: #33ff66;
            --p31-hot: #66ffaa;
            --p31-mid: #22cc44;
            --p31-dim: #0f8822;
            --p31-ghost: #052210;
            --p31-decay: #ffb347;
            --p31-decay-dim: #cc7722;
            /* Tube glass */
            --tube-black: #050803;
            --tube-deep: #080d05;
            --tube-bezel: #0d1208;
            /* Legacy mappings */
            --bg-dark: var(--tube-black);
            --bg-card: var(--tube-deep);
            --bg-sidebar: var(--tube-black);
            --border: var(--p31-ghost);
            --text: var(--p31-mid);
            --text-dim: var(--p31-dim);
            --primary: var(--p31-peak);
            --cyan: var(--p31-peak);
            --green: var(--p31-peak);
            --red: #ff4466;
            --yellow: var(--p31-decay);
            --orange: var(--p31-decay-dim);
            --purple: #a371f7;
            /* Bloom effects */
            --bloom-text: 0 0 2px var(--p31-peak), 0 0 6px var(--p31-peak), 0 0 14px rgba(51,255,102,0.5);
            --bloom-soft: 0 0 6px var(--p31-peak), 0 0 14px rgba(51,255,102,0.5);
            --bloom-amber: 0 0 3px var(--p31-decay), 0 0 10px rgba(255,179,71,0.4);
        }"""

# New body styles
CRT_BODY_STYLES = """body {
            font-family: 'Courier Prime', 'Courier New', monospace;
            background: var(--tube-black);
            background-image: radial-gradient(ellipse at 50% 40%, rgba(51,255,102,0.025) 0%, transparent 70%);
            color: var(--p31-mid);
            display: flex;
            min-height: 100vh;
        }"""

# Additional CRT styles to add
CRT_ADDITIONAL_STYLES = """
        /* CRT Enhancements */
        .main { margin-left: 220px; padding: 1.5rem; }

        .header h1 {
            color: var(--p31-hot);
            text-shadow: var(--bloom-text);
            font-weight: 700;
            letter-spacing: 0.05em;
        }

        .badge {
            font-family: 'Courier Prime', monospace;
            letter-spacing: 0.1em;
            text-transform: uppercase;
            border: 1px solid;
        }
        .badge-blue, .badge-primary { background: rgba(51,255,102,0.1); border-color: var(--p31-peak); color: var(--p31-peak); }
        .badge-green { background: rgba(51,255,102,0.15); border-color: var(--p31-peak); color: var(--p31-peak); text-shadow: var(--bloom-soft); }
        .badge-cyan { background: rgba(51,255,102,0.1); border-color: var(--p31-mid); color: var(--p31-mid); }
        .badge-purple { background: rgba(163,113,247,0.1); border-color: #a371f7; color: #a371f7; }
        .badge-yellow, .badge-amber { background: rgba(255,179,71,0.1); border-color: var(--p31-decay); color: var(--p31-decay); }
        .badge-red { background: rgba(255,68,102,0.1); border-color: #ff4466; color: #ff4466; }

        .btn {
            font-family: 'Courier Prime', monospace;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            border: 1px solid var(--p31-ghost);
            background: var(--tube-deep);
            color: var(--p31-mid);
            transition: all 0.2s;
        }
        .btn:hover {
            border-color: var(--p31-dim);
            color: var(--p31-peak);
            text-shadow: var(--bloom-soft);
            box-shadow: 0 0 12px rgba(51,255,102,0.1);
        }
        .btn-green, .btn-primary, .btn.primary, .btn.success {
            border-color: var(--p31-peak);
            color: var(--p31-peak);
            background: rgba(51,255,102,0.1);
        }
        .btn-green:hover, .btn-primary:hover, .btn.primary:hover, .btn.success:hover {
            background: rgba(51,255,102,0.2);
            box-shadow: 0 0 16px rgba(51,255,102,0.2);
        }
        .btn-red, .btn.danger {
            border-color: #ff4466;
            color: #ff4466;
            background: rgba(255,68,102,0.1);
        }
        .btn-red:hover, .btn.danger:hover {
            background: rgba(255,68,102,0.2);
        }
        .btn-blue {
            border-color: var(--p31-mid);
            color: var(--p31-mid);
            background: rgba(51,255,102,0.05);
        }
        .btn-blue:hover {
            border-color: var(--p31-peak);
            color: var(--p31-peak);
        }

        .card {
            background: var(--tube-deep);
            border: 1px solid var(--p31-ghost);
            box-shadow: inset 0 0 20px rgba(0,0,0,0.3);
        }
        .card:hover {
            border-color: var(--p31-dim);
            box-shadow: 0 0 8px rgba(51,255,102,0.05), inset 0 0 20px rgba(0,0,0,0.3);
        }
        .card-title, .card-header h2 {
            color: var(--p31-decay);
            text-shadow: var(--bloom-amber);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            font-size: 0.85rem;
        }

        .stat-card {
            background: var(--tube-deep);
            border: 1px solid var(--p31-ghost);
        }
        .stat-value, .stat-card .value {
            text-shadow: 0 0 10px currentColor;
        }
        .stat-label, .stat-card .label {
            color: var(--p31-dim);
            letter-spacing: 0.15em;
        }
        .stat-card.cyan .value, .stat-card.green .value { color: var(--p31-peak); }
        .stat-card.yellow .value { color: var(--p31-decay); }
        .stat-card.red .value { color: #ff4466; }

        table, .table {
            font-family: 'Courier Prime', monospace;
        }
        th, .table th {
            color: var(--p31-decay);
            text-shadow: var(--bloom-amber);
            letter-spacing: 0.15em;
            border-bottom: 1px solid var(--p31-ghost);
        }
        td, .table td {
            border-bottom: 1px solid var(--p31-ghost);
            color: var(--p31-mid);
        }
        tr:hover, .table tr:hover {
            background: rgba(51,255,102,0.03);
        }

        .status-dot.active, .status-running {
            color: var(--p31-peak);
            text-shadow: var(--bloom-soft);
        }
        .status-dot.active {
            background: var(--p31-peak);
            box-shadow: 0 0 8px var(--p31-peak);
        }

        .toast {
            background: var(--tube-deep);
            border: 1px solid var(--p31-dim);
            font-family: 'Courier Prime', monospace;
        }
        .toast-success { border-color: var(--p31-peak); }
        .toast-error { border-color: #ff4466; }

        .modal {
            background: rgba(0,0,0,0.85);
        }
        .modal-content {
            background: var(--tube-deep);
            border: 1px solid var(--p31-dim);
            box-shadow: 0 0 30px rgba(51,255,102,0.1);
        }
        .modal-title {
            color: var(--p31-decay);
            text-shadow: var(--bloom-amber);
            letter-spacing: 0.1em;
        }

        .tabs {
            background: var(--tube-deep);
            border-bottom: 1px solid var(--p31-ghost);
        }
        .tab {
            color: var(--p31-dim);
            letter-spacing: 0.1em;
            text-transform: uppercase;
            font-size: 0.8rem;
        }
        .tab:hover { color: var(--p31-mid); }
        .tab.active {
            color: var(--p31-peak);
            text-shadow: var(--bloom-soft);
            border-bottom-color: var(--p31-peak);
        }

        input, select, textarea {
            font-family: 'Courier Prime', monospace;
            background: var(--tube-black);
            border: 1px solid var(--p31-ghost);
            color: var(--p31-mid);
            padding: 0.5rem;
        }
        input:focus, select:focus, textarea:focus {
            outline: none;
            border-color: var(--p31-dim);
            box-shadow: 0 0 8px rgba(51,255,102,0.1);
        }

        /* Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--tube-black); }
        ::-webkit-scrollbar-thumb { background: var(--p31-dim); }
        ::-webkit-scrollbar-thumb:hover { background: var(--p31-mid); }

        /* Empty states */
        .empty { color: var(--p31-dim); }

        @media (max-width: 768px) {
            .main { margin-left: 0; }
        }"""

def process_file(filepath):
    """Process a single HTML file"""
    print(f"  Processing: {filepath}")

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original = content

    # Add CRT system CSS link after sidebar.css
    if 'crt-system.css' not in content:
        content = content.replace(
            '<link rel="stylesheet" href="/shared/sidebar.css">',
            '<link rel="stylesheet" href="/shared/crt-system.css">\n    <link rel="stylesheet" href="/shared/sidebar.css">'
        )

    # Add Google Fonts import if not present
    if 'Courier+Prime' not in content:
        content = re.sub(
            r'(<link rel="stylesheet" href="/shared/crt-system.css">)',
            r'<link rel="preconnect" href="https://fonts.googleapis.com">\n    <link href="https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap" rel="stylesheet">\n    \1',
            content
        )

    # Replace old :root variables with CRT variables
    content = re.sub(
        r':root\s*\{[^}]+\}',
        CRT_ROOT_VARS,
        content
    )

    # Update body styles
    content = re.sub(
        r'body\s*\{[^}]+font-family:[^}]+\}',
        CRT_BODY_STYLES,
        content
    )

    # Add CRT additional styles before </style>
    if 'CRT Enhancements' not in content:
        content = content.replace('</style>', CRT_ADDITIONAL_STYLES + '\n    </style>')

    # Add CRT engine script before </body>
    if 'crt-engine.js' not in content:
        content = content.replace(
            '</body>',
            '    <script src="/shared/crt-engine.js"></script>\n</body>'
        )

    # Update body tag to include CRT classes
    if 'crt-body' not in content:
        content = re.sub(
            r'<body>',
            '<body class="crt-body crt-scanlines">',
            content
        )
        content = re.sub(
            r'<body class="([^"]*)"',
            r'<body class="crt-body crt-scanlines \1"',
            content
        )

    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pattern = os.path.join(base_dir, 'packages', 'secubox-*', 'www', '**', 'index.html')

    files = glob.glob(pattern, recursive=True)
    print(f"Found {len(files)} HTML files to process")

    updated = 0
    for filepath in sorted(files):
        if process_file(filepath):
            updated += 1

    print(f"\nUpdated {updated}/{len(files)} files")

if __name__ == '__main__':
    main()
