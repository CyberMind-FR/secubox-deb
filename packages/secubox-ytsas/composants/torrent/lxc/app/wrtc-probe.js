// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: secubox-torrent :: wrtc-probe.js — CyberMind https://cybermind.fr
//
// Exits 0 and prints WEBRTC_AVAILABLE=true if @roamhq/wrtc loads a
// RTCPeerConnection on this arch; exits 0 with =false otherwise (fallback).
try {
  const wrtc = await import('@roamhq/wrtc');
  const pc = new wrtc.default.RTCPeerConnection();
  pc.close();
  console.log('WEBRTC_AVAILABLE=true');
} catch (e) {
  console.log('WEBRTC_AVAILABLE=false');
  console.error('wrtc load failed:', e.message);
}
