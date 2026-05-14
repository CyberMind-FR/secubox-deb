// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/common/js/config.js
//
// Runtime configuration for the round/ dashboard transport layer.
// API base URLs (OTG and WiFi), endpoint paths, login credentials, JWT
// renewal interval, probe thresholds, SIMULATE flag.
//
// Consumed by transport-manager.js (Task 7) — must load BEFORE it.
//
// deploy.sh patches LOGIN_PASS and (optionally) SIMULATE/API_OTG_BASE
// for production deployments. Defaults shipped here are dev-safe.

const CFG = {
  API_OTG_BASE:  'http://10.55.0.1:8000',
  API_WIFI_BASE: 'http://secubox.local:8000',
  ENDPOINT_METRICS: '/api/v1/system/metrics',
  ENDPOINT_LOGIN:   '/api/v1/auth/token',
  LOGIN_USER: 'dashboard', LOGIN_PASS: 'secubox-round',
  REFRESH_INTERVAL: 2000, JWT_RENEW_BEFORE_MS: 30000,
  OTG_FAILOVER_THRESHOLD: 3, PROBE_INTERVAL: 30000,
  SIMULATE: true,
};

if (typeof window !== 'undefined') { window.CFG = CFG; }
