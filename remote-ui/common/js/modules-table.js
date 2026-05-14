// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/modules-table.js
//
// Canonical ring-rendering table for round/'s 480×480 dashboard.
// Six entries, ordered AUTH/WALL/BOOT/MIND/ROOT/MESH (hamiltonian path).
// Each entry: { color, r (radius px), w (stroke width px),
//               fn (state→[0..1] value extractor) }.
//
// Also exports CX/CY (canvas centre, 240,240) and SA (start angle, -π/2).
//
// square/'s right-column native widgets do NOT consume this table directly —
// they re-derive module metadata in Python from /api/v1/system/metrics. RINGS
// remains a round/-specific rendering aid.

const CX=240,CY=240,SA=-Math.PI/2;
const RINGS=[
  {color:'#C04E24',r:214,w:5,fn:s=>s.cpu/100},
  {color:'#9A6010',r:201,w:5,fn:s=>s.mem/100},
  {color:'#803018',r:188,w:5,fn:s=>s.disk/100},
  {color:'#3D35A0',r:175,w:5,fn:s=>Math.min(1,s.load/4)},
  {color:'#0A5840',r:162,w:5,fn:s=>Math.min(1,Math.max(0,(s.temp-35)/50))},
  {color:'#104A88',r:149,w:5,fn:s=>Math.min(1,Math.max(0,(s.net+90)/70))},
];

if (typeof window !== 'undefined') {
  window.CX = CX;
  window.CY = CY;
  window.SA = SA;
  window.RINGS = RINGS;
}
