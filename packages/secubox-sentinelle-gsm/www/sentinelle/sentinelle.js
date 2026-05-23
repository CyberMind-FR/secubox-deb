// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gerald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.

/**
 * SecuBox-Deb :: SENTINELLE-GSM :: standalone webui logic.
 *
 * - Live alerts via SSE (text/event-stream, "alert" events).
 * - Browser Notification API for desktop popups (requires user gesture).
 * - Web Audio API synthesised beep (no static asset).
 * - CRUD against /api/v1/sensor/gsm/* (root-relative; nginx adds the prefix).
 *
 * No framework, no CDN — pure vanilla, consistent with other SecuBox webuis.
 */

(function () {
  "use strict";

  const API = "/api/v1/sensor/gsm";
  const MAX_ROWS = 200;
  const BEEP_MUTE_KEY = "sgsm.beep.muted";

  // ── DOM refs ────────────────────────────────────────────────────────
  const els = {
    streamDot:     document.getElementById("stream-dot"),
    streamStatus:  document.getElementById("stream-status"),
    trustedCount:  document.getElementById("trusted-count"),
    lastAlertTs:   document.getElementById("last-alert-ts"),
    notifDot:      document.getElementById("notif-dot"),
    notifStatus:   document.getElementById("notif-status"),
    alertsTbody:   document.getElementById("alerts-tbody"),
    alertsCount:   document.getElementById("alerts-count"),
    trustedTbody:  document.getElementById("trusted-tbody"),
    btnRefresh:    document.getElementById("btn-refresh-alerts"),
    btnAdd:        document.getElementById("btn-add-trusted"),
    btnTest:       document.getElementById("btn-test-alert"),
    btnNotif:      document.getElementById("btn-request-notif"),
    btnMute:       document.getElementById("btn-mute-beep"),
    logsPre:       document.getElementById("logs-pre"),
    logsCount:     document.getElementById("logs-count"),
    toggleAutoscroll: document.getElementById("toggle-autoscroll"),
    btnClearLogs:  document.getElementById("btn-clear-logs"),
    muteLabel:     document.getElementById("mute-label"),
    modal:         document.getElementById("modal-add"),
    modalForm:     document.getElementById("form-add-trusted"),
    fieldImsi:     document.getElementById("field-imsi"),
    fieldLabel:    document.getElementById("field-label"),
    btnCancelAdd:  document.getElementById("btn-cancel-add"),
    toast:         document.getElementById("toast"),
    // v0.3 scan control + observations
    btnScanStart:    document.getElementById("btn-scan-start"),
    btnScanStop:     document.getElementById("btn-scan-stop"),
    scanFreqInput:   document.getElementById("scan-freq"),
    scanStateDot:    document.getElementById("scan-state-dot"),
    scanStateText:   document.getElementById("scan-state-text"),
    scanFreqCell:    document.getElementById("scan-freq-cell"),
    scanPidCell:     document.getElementById("scan-pid-cell"),
    scanStartedCell: document.getElementById("scan-started-cell"),
    scanStderrTail:  document.getElementById("scan-stderr-tail"),
    obsCount:        document.getElementById("obs-count"),
    obsTbody:        document.getElementById("obs-tbody"),
    btnRefreshObs:   document.getElementById("btn-refresh-obs"),
    // v0.3.1 baseline + scoring
    baselineCount:        document.getElementById("baseline-count"),
    baselineTbody:        document.getElementById("baseline-tbody"),
    btnRefreshBaseline:   document.getElementById("btn-refresh-baseline"),
    btnBaselineLearn:     document.getElementById("btn-baseline-learn"),
    thresholdGrid:        document.getElementById("threshold-grid"),
    btnRefreshScoring:    document.getElementById("btn-refresh-scoring"),
    btnSaveScoring:       document.getElementById("btn-save-scoring"),
    // v0.4.0 RDS / FM
    btnRdsStart:          document.getElementById("btn-rds-start"),
    btnRdsStop:           document.getElementById("btn-rds-stop"),
    btnRdsSweep:          document.getElementById("btn-rds-sweep"),
    btnRdsSweepCancel:    document.getElementById("btn-rds-sweep-cancel"),
    btnRdsRefreshStations:document.getElementById("btn-rds-refresh-stations"),
    rdsFreqInput:         document.getElementById("rds-freq"),
    rdsPpmInput:          document.getElementById("rds-ppm"),
    rdsGainInput:         document.getElementById("rds-gain"),
    rdsStateDot:          document.getElementById("rds-state-dot"),
    rdsStateText:         document.getElementById("rds-state-text"),
    rdsFreqCell:          document.getElementById("rds-freq-cell"),
    rdsFramesCell:        document.getElementById("rds-frames-cell"),
    rdsPiCell:            document.getElementById("rds-pi-cell"),
    rdsPsCell:            document.getElementById("rds-ps-cell"),
    rdsStationsCount:     document.getElementById("rds-stations-count"),
    rdsStationsTbody:     document.getElementById("rds-stations-tbody"),
    rdsSweepProgress:     document.getElementById("rds-sweep-progress"),
    rdsSweepState:        document.getElementById("rds-sweep-state"),
    rdsSweepStep:         document.getElementById("rds-sweep-step"),
    rdsSweepCurrent:      document.getElementById("rds-sweep-current"),
    rdsSweepFound:        document.getElementById("rds-sweep-found"),
  };

  // ── state ───────────────────────────────────────────────────────────
  let alertCount = 0;
  let beepMuted = (localStorage.getItem(BEEP_MUTE_KEY) === "1");
  let _audioCtx = null;
  let _streamErrorTimer = null;
  let _scanRunning = false;
  let _scanPollTimer = null;

  // ── utils ───────────────────────────────────────────────────────────
  function fmtTime(epochSec) {
    if (!epochSec) return "—";
    const d = new Date(epochSec * 1000);
    const hh = String(d.getHours()).padStart(2, "0");
    const mm = String(d.getMinutes()).padStart(2, "0");
    const ss = String(d.getSeconds()).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
  }

  function fmtDateTime(epochSec) {
    if (!epochSec) return "—";
    const d = new Date(epochSec * 1000);
    return d.toLocaleString("sv-SE");  // ISO-ish, locale-stable
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function shortId(id) {
    const s = String(id || "");
    return s.length > 8 ? s.slice(0, 8) : s;
  }

  function scoreClass(score) {
    const n = Number(score) || 0;
    if (n >= 70) return "high";
    if (n >= 40) return "med";
    return "low";
  }

  function toast(msg, kind) {
    els.toast.textContent = msg;
    els.toast.className = "toast show " + (kind || "");
    clearTimeout(toast._t);
    toast._t = setTimeout(() => {
      els.toast.classList.remove("show");
    }, 3000);
  }

  async function apiFetch(path, opts) {
    const res = await fetch(API + path, opts || {});
    let body = null;
    try { body = await res.json(); } catch (_) { /* ignore */ }
    if (!res.ok) {
      const msg = (body && body.detail) || `HTTP ${res.status}`;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return body;
  }

  // ── notifications ───────────────────────────────────────────────────
  function refreshNotifStatus() {
    if (!("Notification" in window)) {
      els.notifStatus.textContent = "unsupported";
      els.notifDot.className = "dot dot-down";
      els.btnNotif.disabled = true;
      return;
    }
    const p = Notification.permission;
    els.notifStatus.textContent = p;
    els.notifDot.className =
      (p === "granted") ? "dot dot-live" :
      (p === "denied")  ? "dot dot-down" :
                          "dot dot-warn";
    if (p === "granted") {
      els.btnNotif.textContent = "Desktop notifications enabled";
      els.btnNotif.disabled = true;
    }
  }

  async function ensureNotificationPermission() {
    // Must be called from a user gesture handler — modern browsers reject
    // permission requests originating from page-load JS.
    if (!("Notification" in window)) return false;
    if (Notification.permission === "granted") return true;
    if (Notification.permission === "denied") return false;
    try {
      const p = await Notification.requestPermission();
      refreshNotifStatus();
      return p === "granted";
    } catch (_) {
      return false;
    }
  }

  function showDesktopAlert(alert) {
    if (!("Notification" in window)) return;
    if (Notification.permission !== "granted") return;
    const title = `SENTINELLE-GSM — score ${alert.score}`;
    let body = `${alert.reason}\ncell ${alert.cell_id} arfcn ${alert.arfcn}`;
    if (alert.trusted_label) body += `\ntargets: ${alert.trusted_label}`;
    try {
      const n = new Notification(title, {
        body: body,
        tag: `sgsm-${alert.id}`,
        // icon path is best-effort; nginx may 404 it, that's fine.
        icon: "/shared/secubox-mind.png",
      });
      n.onclick = () => { window.focus(); n.close(); };
    } catch (e) {
      // Some Linux desktops without a notification daemon throw; swallow.
      console.warn("Notification failed:", e);
    }
  }

  // ── beep (Web Audio synthesised, no asset) ──────────────────────────
  function playBeep() {
    if (beepMuted) return;
    try {
      if (!_audioCtx) {
        const AC = window.AudioContext || window.webkitAudioContext;
        if (!AC) return;
        _audioCtx = new AC();
      }
      if (_audioCtx.state === "suspended") _audioCtx.resume();
      const ctx = _audioCtx;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(880, ctx.currentTime);
      // Short envelope: 0 → 0.18 → 0 over 200ms (avoids click)
      gain.gain.setValueAtTime(0.0001, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.18, ctx.currentTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.20);
      osc.connect(gain).connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.22);
    } catch (e) {
      console.warn("Beep failed:", e);
    }
  }

  function refreshMuteUi() {
    els.btnMute.setAttribute("aria-pressed", beepMuted ? "true" : "false");
    els.muteLabel.textContent = beepMuted ? "Beep: off" : "Beep: on";
  }

  function toggleMute() {
    beepMuted = !beepMuted;
    localStorage.setItem(BEEP_MUTE_KEY, beepMuted ? "1" : "0");
    refreshMuteUi();
  }

  // ── alerts table ────────────────────────────────────────────────────
  function clearAlertsPlaceholder() {
    const empty = els.alertsTbody.querySelector("tr.empty");
    if (empty) empty.remove();
  }

  function buildAlertRow(alert) {
    const tr = document.createElement("tr");
    tr.dataset.alertId = alert.id;
    const targetCell = alert.trusted_label
      ? `<span class="trusted-chip">${escapeHtml(alert.trusted_label)}</span>`
      : '<span style="color:var(--text-dim)">—</span>';
    tr.innerHTML =
      `<td class="col-time">${escapeHtml(fmtTime(alert.ts))}</td>` +
      `<td class="col-cell">${escapeHtml(alert.cell_id)}</td>` +
      `<td class="col-arfcn">${escapeHtml(alert.arfcn)}</td>` +
      `<td><span class="score-chip ${scoreClass(alert.score)}">${escapeHtml(alert.score)}</span></td>` +
      `<td>${escapeHtml(alert.reason)}</td>` +
      `<td>${targetCell}</td>`;
    return tr;
  }

  function prependToAlertList(alert) {
    clearAlertsPlaceholder();
    const row = buildAlertRow(alert);
    els.alertsTbody.insertBefore(row, els.alertsTbody.firstChild);
    while (els.alertsTbody.children.length > MAX_ROWS) {
      els.alertsTbody.removeChild(els.alertsTbody.lastChild);
    }
    alertCount += 1;
    els.alertsCount.textContent = String(alertCount);
    els.lastAlertTs.textContent = fmtDateTime(alert.ts);
  }

  async function loadAlertHistory() {
    try {
      const data = await apiFetch("/alerts?limit=100");
      const alerts = (data && data.alerts) || [];
      els.alertsTbody.innerHTML = "";
      if (alerts.length === 0) {
        els.alertsTbody.innerHTML =
          '<tr class="empty"><td colspan="6">no alerts in history — waiting for stream…</td></tr>';
        alertCount = 0;
        els.alertsCount.textContent = "0";
        els.lastAlertTs.textContent = "—";
        return;
      }
      // newest first
      alerts.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      alerts.forEach((a) => els.alertsTbody.appendChild(buildAlertRow(a)));
      alertCount = alerts.length;
      els.alertsCount.textContent = String(alertCount);
      els.lastAlertTs.textContent = fmtDateTime(alerts[0].ts);
    } catch (e) {
      toast("Failed to load alert history: " + e.message, "err");
    }
  }

  // ── SSE stream ──────────────────────────────────────────────────────
  function setStreamStatus(state, label) {
    els.streamStatus.textContent = label;
    els.streamDot.className = "dot " + state;
  }

  function startAlertStream() {
    setStreamStatus("dot-warn", "connecting…");
    const es = new EventSource(API + "/alerts/stream");
    es.addEventListener("open", () => {
      setStreamStatus("dot-live", "live");
    });
    es.addEventListener("alert", (e) => {
      let alert;
      try { alert = JSON.parse(e.data); }
      catch (err) { console.warn("bad SSE payload:", err); return; }
      prependToAlertList(alert);
      showDesktopAlert(alert);
      playBeep();
    });
    es.onerror = () => {
      // EventSource auto-reconnects; just surface the state.
      setStreamStatus("dot-warn", "reconnecting…");
      clearTimeout(_streamErrorTimer);
      _streamErrorTimer = setTimeout(() => {
        // If the readyState is OPEN by then, restore "live".
        if (es.readyState === EventSource.OPEN) {
          setStreamStatus("dot-live", "live");
        } else if (es.readyState === EventSource.CLOSED) {
          setStreamStatus("dot-down", "closed");
        }
      }, 2500);
    };
    return es;
  }

  // ── journal live stream (v0.2.2) ────────────────────────────────────
  const LOGS_MAX_LINES = 500;     // cap memory usage on long sessions
  const _logsState = {
    es: null,
    count: 0,
    autoscroll: true,
  };

  function _priorityClass(prio) {
    // syslog: 0 emerg, 1 alert, 2 crit, 3 err, 4 warn, 5 notice, 6 info, 7 debug
    if (prio <= 3) return "log-err";
    if (prio === 4) return "log-warn";
    if (prio === 7) return "log-debug";
    return "log-info";
  }

  function _formatLogTs(ts) {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    const pad = n => String(n).padStart(2, "0");
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function appendLogLine(entry) {
    const pre = els.logsPre;
    if (!pre) return;
    if (_logsState.count === 0) pre.textContent = "";
    const line = document.createElement("span");
    line.className = "log-line " + _priorityClass(entry.priority || 6);
    line.textContent = "[" + _formatLogTs(entry.ts) + "] " + (entry.message || "");
    pre.appendChild(line);
    pre.appendChild(document.createTextNode("\n"));
    _logsState.count += 1;
    if (els.logsCount) els.logsCount.textContent = _logsState.count;

    // Trim the head if we exceed the cap, keeping the tail.
    while (_logsState.count > LOGS_MAX_LINES) {
      pre.removeChild(pre.firstChild);            // span
      if (pre.firstChild && pre.firstChild.nodeType === Node.TEXT_NODE) {
        pre.removeChild(pre.firstChild);          // the newline text
      }
      _logsState.count -= 1;
    }
    if (_logsState.autoscroll) pre.scrollTop = pre.scrollHeight;
  }

  function startJournalStream() {
    if (_logsState.es) try { _logsState.es.close(); } catch (e) { /* ignore */ }
    const es = new EventSource(API + "/journal/stream");
    es.addEventListener("log", (e) => {
      let entry;
      try { entry = JSON.parse(e.data); }
      catch (err) { return; }
      appendLogLine(entry);
    });
    es.onerror = () => { /* auto-reconnect; no UI noise */ };
    _logsState.es = es;
    return es;
  }

  function clearLogs() {
    if (els.logsPre) els.logsPre.textContent = "(cleared)";
    _logsState.count = 0;
    if (els.logsCount) els.logsCount.textContent = "0";
  }

  // ── trusted phones ──────────────────────────────────────────────────
  function buildTrustedRow(phone) {
    const tr = document.createElement("tr");
    tr.dataset.phoneId = phone.id;
    tr.innerHTML =
      `<td class="col-id" title="${escapeHtml(phone.id)}">${escapeHtml(shortId(phone.id))}</td>` +
      `<td>${escapeHtml(phone.label || "")}</td>` +
      `<td class="mono">${escapeHtml(fmtDateTime(phone.added_at))}</td>` +
      `<td class="actions-col">` +
        `<button class="btn danger row-action" type="button" data-action="delete">Delete</button>` +
      `</td>`;
    return tr;
  }

  async function loadTrusted() {
    try {
      const data = await apiFetch("/trusted");
      const phones = (data && data.phones) || [];
      els.trustedTbody.innerHTML = "";
      if (phones.length === 0) {
        els.trustedTbody.innerHTML =
          '<tr class="empty"><td colspan="4">no trusted phones — click "+ Add phone" to register one</td></tr>';
      } else {
        phones.sort((a, b) => (b.added_at || 0) - (a.added_at || 0));
        phones.forEach((p) => els.trustedTbody.appendChild(buildTrustedRow(p)));
      }
      els.trustedCount.textContent = String(phones.length);
    } catch (e) {
      toast("Failed to load trusted phones: " + e.message, "err");
      els.trustedCount.textContent = "?";
    }
  }

  async function addTrusted(imsi, label) {
    return apiFetch("/trusted", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ imsi: imsi, label: label }),
    });
  }

  async function deleteTrusted(id) {
    return apiFetch("/trusted/" + encodeURIComponent(id), { method: "DELETE" });
  }

  async function fireTestAlert() {
    return apiFetch("/alerts/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
  }

  // ── scan control + observations (v0.3) ──────────────────────────────
  function _formatScanTs(epoch) {
    if (!epoch) return "—";
    const d = new Date(epoch * 1000);
    const pad = n => String(n).padStart(2, "0");
    return pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
  }

  function _renderScanStatus(st) {
    const running = !!(st && st.running);
    _scanRunning = running;
    if (els.scanStateDot) {
      els.scanStateDot.className = "dot " + (running ? "dot-live" : "dot-idle");
    }
    if (els.scanStateText) {
      els.scanStateText.textContent = running ? "running" : "idle";
    }
    if (els.scanFreqCell) {
      els.scanFreqCell.textContent = (st && st.freq) ? String(st.freq) : "—";
    }
    if (els.scanPidCell) {
      els.scanPidCell.textContent = (st && st.pid) ? String(st.pid) : "—";
    }
    if (els.scanStartedCell) {
      els.scanStartedCell.textContent = (st && st.started_at)
        ? _formatScanTs(st.started_at) : "—";
    }
    if (els.scanStderrTail) {
      const tail = (st && st.stderr_tail) ? String(st.stderr_tail) : "";
      els.scanStderrTail.textContent = tail.length ? tail : "(no output)";
    }
    if (els.btnScanStart) els.btnScanStart.disabled = running;
    if (els.btnScanStop)  els.btnScanStop.disabled  = !running;
  }

  async function loadScanStatus() {
    try {
      const st = await apiFetch("/scan/status");
      _renderScanStatus(st);
    } catch (e) {
      if (els.scanStateDot) els.scanStateDot.className = "dot dot-down";
      if (els.scanStateText) els.scanStateText.textContent = "error";
      console.warn("scan status failed:", e);
    }
  }

  async function startScan() {
    const freq = (els.scanFreqInput && els.scanFreqInput.value || "").trim();
    if (!freq) {
      toast("Enter a frequency (e.g. 925.4M)", "warn");
      return;
    }
    try {
      const st = await apiFetch("/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ freq: freq }),
      });
      _renderScanStatus(st);
      toast("Scan started on " + freq, "ok");
      // immediately refresh observations so the table comes alive
      loadObservations();
    } catch (e) {
      toast("Start failed: " + e.message, "err");
      loadScanStatus();
    }
  }

  async function stopScan() {
    try {
      const st = await apiFetch("/scan/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      _renderScanStatus(st);
      toast("Scan stopped", "ok");
    } catch (e) {
      toast("Stop failed: " + e.message, "err");
      loadScanStatus();
    }
  }

  function _buildObsRow(s) {
    const tr = document.createElement("tr");
    const fmt = (v) => (v === null || v === undefined || v === "") ? "—" : String(v);
    tr.innerHTML =
      `<td class="col-cell">${escapeHtml(s.cell_id)}</td>` +
      `<td class="col-arfcn">${escapeHtml(fmt(s.arfcn))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.mcc))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.mnc))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.lac))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.ci))}</td>` +
      `<td class="mono">${escapeHtml(fmtDateTime(s.first_seen))}</td>` +
      `<td class="mono">${escapeHtml(fmtDateTime(s.last_seen))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.sighting_count))}</td>`;
    return tr;
  }

  async function loadObservations() {
    try {
      const data = await apiFetch("/observations?limit=200");
      const sightings = (data && data.sightings) || [];
      els.obsTbody.innerHTML = "";
      if (sightings.length === 0) {
        els.obsTbody.innerHTML =
          '<tr class="empty"><td colspan="9">no observations yet — start a scan</td></tr>';
      } else {
        sightings.forEach((s) => els.obsTbody.appendChild(_buildObsRow(s)));
      }
      if (els.obsCount) els.obsCount.textContent = String(sightings.length);
    } catch (e) {
      console.warn("observations load failed:", e);
      // soft-fail: don't toast on every 10s tick
    }
  }

  // ── baseline + scoring (v0.3.1) ─────────────────────────────────────
  function _buildBaselineRow(c) {
    const tr = document.createElement("tr");
    const fmt = (v) => (v === null || v === undefined || v === "") ? "—" : String(v);
    tr.innerHTML =
      `<td class="col-cell">${escapeHtml(c.cell_id)}</td>` +
      `<td class="mono">${escapeHtml(fmt(c.mcc))}</td>` +
      `<td class="mono">${escapeHtml(fmt(c.mnc))}</td>` +
      `<td class="mono">${escapeHtml(fmt(c.lac))}</td>` +
      `<td class="mono">${escapeHtml(fmt(c.arfcn))}</td>` +
      `<td class="mono">${escapeHtml(fmt(c.cipher_a5))}</td>` +
      `<td class="mono">${escapeHtml(fmt(c.learn_count))}</td>` +
      `<td class="mono">${escapeHtml(fmtDateTime(c.last_learned))}</td>`;
    return tr;
  }

  function renderBaselineTable(cells) {
    if (!els.baselineTbody) return;
    els.baselineTbody.innerHTML = "";
    if (!cells || cells.length === 0) {
      els.baselineTbody.innerHTML =
        '<tr class="empty"><td colspan="8">no baseline yet — start a scan + click "Start learn"</td></tr>';
      return;
    }
    cells.forEach((c) => els.baselineTbody.appendChild(_buildBaselineRow(c)));
  }

  async function loadBaseline() {
    try {
      const r = await fetch(API + "/baseline?limit=200", { credentials: "include" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      const cells = j.cells || [];
      if (els.baselineCount) els.baselineCount.textContent = String(cells.length);
      renderBaselineTable(cells);
    } catch (e) {
      console.warn("loadBaseline failed:", e);
    }
  }

  let _baselineLearnPollTimer = null;
  async function startBaselineLearn() {
    try {
      const r = await fetch(API + "/baseline/learn", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sweep_seconds: 300 }),
        credentials: "include",
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      toast("baseline learn mode armed for 5 min", "ok");
      // re-poll baseline every 15s for 5 min so the table fills as cells graduate
      if (_baselineLearnPollTimer) clearInterval(_baselineLearnPollTimer);
      let ticks = 0;
      _baselineLearnPollTimer = setInterval(() => {
        loadBaseline();
        ticks += 1;
        if (ticks >= 20) {              // 20 * 15s = 5 min
          clearInterval(_baselineLearnPollTimer);
          _baselineLearnPollTimer = null;
        }
      }, 15000);
    } catch (e) {
      toast("baseline learn failed: " + e.message, "err");
    }
  }

  // Local cache of current scoring threshold form values, keyed by heuristic
  // name. Each value is the full threshold object (enabled, score, plus any
  // heuristic-specific fields the backend cares about).
  let _thresholdState = {};

  function _clampScore(n) {
    n = Number(n);
    if (!Number.isFinite(n)) return 0;
    if (n < 0) return 0;
    if (n > 100) return 100;
    return Math.round(n);
  }

  function renderThresholdGrid(thresholds) {
    const grid = els.thresholdGrid;
    if (!grid) return;
    grid.innerHTML = "";
    const names = Object.keys(thresholds || {}).sort();
    if (names.length === 0) {
      grid.innerHTML = '<div class="empty">no scoring heuristics defined</div>';
      return;
    }
    names.forEach((name) => {
      const t = thresholds[name] || {};
      const enabled = !!t.enabled;
      const score = _clampScore(t.score);
      const row = document.createElement("div");
      row.className = "threshold-row";
      row.innerHTML =
        `<span class="threshold-name">${escapeHtml(name)}</span>` +
        `<label><input type="checkbox" data-heur="${escapeHtml(name)}" data-field="enabled"` +
          (enabled ? " checked" : "") + `> enabled</label>` +
        `<label>score <input type="number" min="0" max="100" step="1"` +
          ` data-heur="${escapeHtml(name)}" data-field="score" value="${score}"></label>`;
      grid.appendChild(row);
    });

    // Wire change listeners. We listen on the grid container (event delegation).
    grid.addEventListener("change", _onThresholdChange);
  }

  function _onThresholdChange(e) {
    const inp = e.target;
    if (!inp || !inp.dataset) return;
    const heur = inp.dataset.heur;
    const field = inp.dataset.field;
    if (!heur || !field) return;
    if (!_thresholdState[heur]) _thresholdState[heur] = {};
    if (field === "enabled") {
      _thresholdState[heur].enabled = !!inp.checked;
    } else if (field === "score") {
      const n = _clampScore(inp.value);
      if (String(n) !== String(inp.value)) inp.value = String(n);
      _thresholdState[heur].score = n;
    }
  }

  async function loadThresholds() {
    try {
      const r = await fetch(API + "/scoring/thresholds", { credentials: "include" });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const j = await r.json();
      const thresholds = j.thresholds || {};
      // Deep-ish copy: keep any backend-only fields so a round-trip POST does
      // not silently drop them. The form only edits enabled + score.
      _thresholdState = {};
      Object.keys(thresholds).forEach((name) => {
        const t = thresholds[name] || {};
        _thresholdState[name] = Object.assign({}, t);
      });
      renderThresholdGrid(thresholds);
    } catch (e) {
      console.warn("loadThresholds failed:", e);
    }
  }

  async function saveThresholds() {
    try {
      // Clamp any out-of-range score values one more time before POST.
      Object.keys(_thresholdState).forEach((name) => {
        if ("score" in _thresholdState[name]) {
          _thresholdState[name].score = _clampScore(_thresholdState[name].score);
        }
      });
      const r = await fetch(API + "/scoring/thresholds", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(_thresholdState),
        credentials: "include",
      });
      if (!r.ok) {
        let detail = "HTTP " + r.status;
        try { const b = await r.json(); if (b && b.detail) detail = b.detail; } catch (_) {}
        throw new Error(detail);
      }
      const j = await r.json();
      const thresholds = j.thresholds || j;
      _thresholdState = {};
      Object.keys(thresholds).forEach((name) => {
        _thresholdState[name] = Object.assign({}, thresholds[name] || {});
      });
      renderThresholdGrid(thresholds);
      toast("scoring thresholds updated", "ok");
    } catch (e) {
      toast("save failed: " + e.message, "err");
    }
  }

  // ── modal ───────────────────────────────────────────────────────────
  function openModal() {
    els.modal.classList.add("show");
    els.modal.setAttribute("aria-hidden", "false");
    setTimeout(() => els.fieldImsi.focus(), 50);
  }
  function closeModal() {
    els.modal.classList.remove("show");
    els.modal.setAttribute("aria-hidden", "true");
    els.modalForm.reset();
  }

  // ── event wiring ────────────────────────────────────────────────────
  function wireEvents() {
    els.btnRefresh.addEventListener("click", loadAlertHistory);

    els.btnAdd.addEventListener("click", openModal);
    els.btnCancelAdd.addEventListener("click", closeModal);
    els.modal.addEventListener("click", (e) => {
      if (e.target === els.modal) closeModal();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && els.modal.classList.contains("show")) closeModal();
    });

    els.modalForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const imsi = els.fieldImsi.value.trim();
      const label = els.fieldLabel.value.trim();
      if (!imsi || !label) return;
      try {
        await addTrusted(imsi, label);
        toast("Trusted phone added", "ok");
        closeModal();
        await loadTrusted();
      } catch (err) {
        toast("Add failed: " + err.message, "err");
      }
    });

    els.trustedTbody.addEventListener("click", async (e) => {
      const btn = e.target.closest('button[data-action="delete"]');
      if (!btn) return;
      const tr = btn.closest("tr");
      const id = tr && tr.dataset.phoneId;
      if (!id) return;
      if (!confirm("Delete trusted phone (id " + shortId(id) + ")?")) return;
      try {
        await deleteTrusted(id);
        toast("Trusted phone removed", "ok");
        await loadTrusted();
      } catch (err) {
        toast("Delete failed: " + err.message, "err");
      }
    });

    els.btnTest.addEventListener("click", async () => {
      // First click also doubles as the user gesture that unlocks AudioContext
      // on browsers that require it.
      if (_audioCtx && _audioCtx.state === "suspended") _audioCtx.resume();
      try {
        const r = await fireTestAlert();
        toast("Test alert fired (id " + (r && r.id) + ")", "ok");
      } catch (err) {
        toast("Test failed: " + err.message, "err");
      }
    });

    els.btnNotif.addEventListener("click", async () => {
      const ok = await ensureNotificationPermission();
      toast(ok ? "Notifications enabled" : "Notifications not granted",
            ok ? "ok" : "warn");
    });

    els.btnMute.addEventListener("click", toggleMute);

    if (els.toggleAutoscroll) {
      els.toggleAutoscroll.addEventListener("change", (e) => {
        _logsState.autoscroll = !!e.target.checked;
      });
    }
    if (els.btnClearLogs) {
      els.btnClearLogs.addEventListener("click", clearLogs);
    }

    // v0.3 scan control + observations
    if (els.btnScanStart) els.btnScanStart.addEventListener("click", startScan);
    if (els.btnScanStop)  els.btnScanStop.addEventListener("click", stopScan);
    if (els.btnRefreshObs) els.btnRefreshObs.addEventListener("click", loadObservations);

    // v0.3.1 baseline + scoring
    if (els.btnRefreshBaseline) els.btnRefreshBaseline.addEventListener("click", loadBaseline);
    if (els.btnBaselineLearn)   els.btnBaselineLearn.addEventListener("click", startBaselineLearn);
    if (els.btnRefreshScoring)  els.btnRefreshScoring.addEventListener("click", loadThresholds);
    if (els.btnSaveScoring)     els.btnSaveScoring.addEventListener("click", saveThresholds);

    // v0.4.0 RDS / FM
    if (els.btnRdsStart)           els.btnRdsStart.addEventListener("click", startRds);
    if (els.btnRdsStop)            els.btnRdsStop.addEventListener("click", stopRds);
    if (els.btnRdsSweep)           els.btnRdsSweep.addEventListener("click", startRdsSweep);
    if (els.btnRdsSweepCancel)     els.btnRdsSweepCancel.addEventListener("click", cancelRdsSweep);
    if (els.btnRdsRefreshStations) els.btnRdsRefreshStations.addEventListener("click", loadRdsStations);
  }

  // ── RDS / FM (v0.4.0) ───────────────────────────────────────────────
  let _rdsRunning = false;
  let _rdsActiveSweepId = null;

  function _renderRdsStatus(st) {
    const running = !!(st && st.running);
    _rdsRunning = running;
    if (els.rdsStateDot) {
      els.rdsStateDot.className = "dot " + (running ? "dot-live" : "dot-idle");
    }
    if (els.rdsStateText) els.rdsStateText.textContent = running ? "running" : "idle";
    if (els.rdsFreqCell)  els.rdsFreqCell.textContent  = (st && st.freq)  ? String(st.freq) : "—";
    if (els.rdsFramesCell) els.rdsFramesCell.textContent = (st && typeof st.frames === "number") ? String(st.frames) : "0";
    if (els.rdsPiCell)    els.rdsPiCell.textContent    = (st && st.last_pi) ? String(st.last_pi) : "—";
    if (els.rdsPsCell)    els.rdsPsCell.textContent    = (st && st.last_ps) ? String(st.last_ps) : "—";
    if (els.btnRdsStart) els.btnRdsStart.disabled = running;
    if (els.btnRdsStop)  els.btnRdsStop.disabled  = !running;
  }

  function _renderRdsSweepProgress(j) {
    if (!els.rdsSweepProgress) return;
    if (!j) {
      els.rdsSweepProgress.hidden = true;
      _rdsActiveSweepId = null;
      return;
    }
    els.rdsSweepProgress.hidden = false;
    if (els.rdsSweepState)   els.rdsSweepState.textContent   = j.state || "—";
    if (els.rdsSweepStep)    els.rdsSweepStep.textContent    =
      (typeof j.step_index === "number" && typeof j.step_total === "number")
        ? (j.step_index + " / " + j.step_total) : "—";
    if (els.rdsSweepCurrent) els.rdsSweepCurrent.textContent = (j.current_freq_mhz != null) ? (j.current_freq_mhz + " MHz") : "—";
    if (els.rdsSweepFound)   els.rdsSweepFound.textContent   = (typeof j.stations_found === "number") ? String(j.stations_found) : "0";
    _rdsActiveSweepId = (j.state && j.state !== "stopped" && j.state !== "failed" && j.state !== "cancelled") ? j.id : null;
    if (els.btnRdsSweep)        els.btnRdsSweep.disabled        = !!_rdsActiveSweepId;
    if (els.btnRdsSweepCancel)  els.btnRdsSweepCancel.disabled  = !_rdsActiveSweepId;
  }

  async function loadRdsStatus() {
    try {
      const st = await apiFetch("/rds/status");
      _renderRdsStatus(st);
    } catch (e) {
      if (els.rdsStateDot)  els.rdsStateDot.className  = "dot dot-down";
      if (els.rdsStateText) els.rdsStateText.textContent = "error";
    }
    try {
      const jobs = await apiFetch("/rds/sweep/jobs?limit=1");
      const job = (jobs && jobs.jobs && jobs.jobs[0]) || null;
      // Show progress only for active sweeps; clear when terminal.
      _renderRdsSweepProgress(job && job.state !== "stopped" && job.state !== "cancelled" && job.state !== "failed" ? job : null);
    } catch (_) { /* ignore — no jobs yet */ }
  }

  function _buildRdsRow(s) {
    const tr = document.createElement("tr");
    const fmt = (v) => (v === null || v === undefined || v === "") ? "—" : String(v);
    const flags = [];
    if (s.tp) flags.push("TP");
    if (s.ta) flags.push("TA");
    tr.innerHTML =
      `<td class="mono">${escapeHtml(fmt(s.pi))}</td>` +
      `<td>${escapeHtml(fmt(s.ps))}</td>` +
      `<td>${escapeHtml(fmt(s.rt))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.pty))}</td>` +
      `<td class="mono">${escapeHtml(flags.join(" / ") || "—")}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.freq))}</td>` +
      `<td class="mono">${escapeHtml(fmt(s.count))}</td>` +
      `<td class="mono">${escapeHtml(fmtDateTime(s.last_seen))}</td>`;
    return tr;
  }

  async function loadRdsStations() {
    if (!els.rdsStationsTbody) return;
    try {
      const data = await apiFetch("/rds/stations?limit=200");
      const stations = (data && data.stations) || [];
      if (els.rdsStationsCount) els.rdsStationsCount.textContent = String(stations.length);
      els.rdsStationsTbody.innerHTML = "";
      if (!stations.length) {
        els.rdsStationsTbody.innerHTML = `<tr class="empty"><td colspan="8">no stations yet — start a sweep or single-freq scan</td></tr>`;
        return;
      }
      const frag = document.createDocumentFragment();
      for (const s of stations) frag.appendChild(_buildRdsRow(s));
      els.rdsStationsTbody.appendChild(frag);
    } catch (e) {
      console.warn("rds stations failed:", e);
    }
  }

  async function startRds() {
    const freq = (els.rdsFreqInput && els.rdsFreqInput.value || "").trim();
    if (!freq) { toast("Enter a frequency (e.g. 100.6M)", "warn"); return; }
    const body = { freq: freq };
    const ppmRaw  = (els.rdsPpmInput  && els.rdsPpmInput.value  || "").trim();
    const gainRaw = (els.rdsGainInput && els.rdsGainInput.value || "").trim();
    if (ppmRaw)  body.ppm  = Number(ppmRaw);
    if (gainRaw) body.gain = Number(gainRaw);
    try {
      const st = await apiFetch("/rds/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      _renderRdsStatus(st);
      toast("RDS scan started on " + freq, "ok");
      loadRdsStations();
    } catch (e) {
      toast("RDS start failed: " + e.message, "err");
      loadRdsStatus();
    }
  }

  async function stopRds() {
    try {
      const st = await apiFetch("/rds/stop", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      _renderRdsStatus(st);
      toast("RDS scan stopped", "ok");
      loadRdsStations();
    } catch (e) {
      toast("RDS stop failed: " + e.message, "err");
      loadRdsStatus();
    }
  }

  async function startRdsSweep() {
    try {
      const job = await apiFetch("/rds/sweep", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      _renderRdsSweepProgress(job);
      toast("RDS sweep launched", "ok");
    } catch (e) {
      toast("Sweep launch failed: " + e.message, "err");
    }
  }

  async function cancelRdsSweep() {
    if (!_rdsActiveSweepId) return;
    try {
      const j = await apiFetch("/rds/sweep/jobs/" + encodeURIComponent(_rdsActiveSweepId) + "/cancel", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      _renderRdsSweepProgress(j);
      toast("Sweep cancelled", "ok");
    } catch (e) {
      toast("Cancel failed: " + e.message, "err");
    }
  }

  // ── init ────────────────────────────────────────────────────────────
  function init() {
    refreshNotifStatus();
    refreshMuteUi();
    wireEvents();
    loadAlertHistory();
    loadTrusted();
    startAlertStream();
    startJournalStream();
    loadScanStatus();
    loadObservations();
    loadBaseline();
    loadThresholds();
    loadRdsStatus();
    loadRdsStations();
    // Background polling every 10s. When no scan is running, we still poll
    // /scan/status (cheap) so the UI catches an externally-started scan,
    // but we skip /observations + /baseline to avoid hitting sqlite for
    // nothing — the tables are already at their post-scan terminal state
    // and the user can hit Refresh manually. Same logic for the RDS half:
    // poll the status, only walk the stations table while something runs.
    _scanPollTimer = setInterval(() => {
      loadScanStatus();
      loadRdsStatus();
      if (_scanRunning) {
        loadObservations();
        loadBaseline();
      }
      if (_rdsRunning || _rdsActiveSweepId) {
        loadRdsStations();
      }
    }, 10000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
