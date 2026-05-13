// remote-ui/square/square-bridge.js
// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// SecuBox-Deb :: remote-ui/square/square-bridge.js
//
// Override TransportManager's onModuleTap / onTransportChange hooks so
// Chromium kiosk forwards events to the PySide6 right column over a
// localhost WebSocket. Loaded by square/'s deployed index.html ONLY —
// round/ standalone doesn't include this file.

(function() {
  const WS_URL = 'ws://127.0.0.1:9090/eye-square';
  let ws = null;
  let queue = [];

  function connect() {
    ws = new WebSocket(WS_URL);
    ws.onopen = () => {
      console.log('[square-bridge] connected');
      while (queue.length > 0) ws.send(queue.shift());
    };
    ws.onerror = (e) => console.warn('[square-bridge] error', e);
    ws.onclose = () => {
      ws = null;
      setTimeout(connect, 2000);  // reconnect with backoff
    };
  }

  function send(payload) {
    const msg = JSON.stringify(payload);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    } else {
      queue.push(msg);
      if (!ws) connect();
    }
  }

  function init() {
    if (typeof TM === 'undefined') {
      console.warn('[square-bridge] TM not defined; waiting');
      setTimeout(init, 200);
      return;
    }
    TM.onModuleTap = (module) => send({ event: 'module:tap', module });
    TM.onTransportChange = (active) => send({ event: 'transport:status', active });
    connect();
  }

  document.addEventListener('DOMContentLoaded', init);
})();
