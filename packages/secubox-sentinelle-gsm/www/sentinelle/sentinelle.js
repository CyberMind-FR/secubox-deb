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
  };

  // ── state ───────────────────────────────────────────────────────────
  let alertCount = 0;
  let beepMuted = (localStorage.getItem(BEEP_MUTE_KEY) === "1");
  let _audioCtx = null;
  let _streamErrorTimer = null;

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
      ? `<span class="target-pill">${escapeHtml(alert.trusted_label)}</span>`
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
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
