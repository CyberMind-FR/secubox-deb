// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// SecuBox Companion :: core/metrics — emoji gauges + human formatters.
//
// Companion is glanced at on a phone, often in passing — raw psutil numbers
// ("disk_percent: 94.5") don't read as urgent fast enough. This module turns
// any percent-ish value into a severity-coded gauge (emoji + colour + bar)
// using PER-KIND thresholds, because a disk at 94% and a cpu at 94% do not
// carry the same risk and must not look the same at a glance.

import { el } from './ui.js';

// [warnAt, critAt] as a 0-100 value, per metric kind. Disk fills up silently
// and is the most dangerous to under-alarm on, so it's the strictest; cpu
// bursts constantly and is tolerated much higher before it means anything.
const THRESHOLDS = {
  cpu:  [70, 90],
  mem:  [75, 90],
  disk: [80, 92],   // 94.5% on this box → correctly reads as crit
  temp: [70, 85],   // °C, reuses the same [warn,crit] shape as a percent scale
  load: [70, 90],   // caller normalises load average to % of core count first
  default: [70, 90],
};

const LEVELS = {
  ok:   { emoji: '🟢', badge: 'ok',   word: 'nominal' },
  warn: { emoji: '🟡', badge: 'warn', word: 'elevated' },
  crit: { emoji: '🔴', badge: 'err',  word: 'critical' },
};

/** Classify a 0-100 value for `kind` into 'ok' | 'warn' | 'crit'. */
export function severity(kind, value) {
  if (value == null || Number.isNaN(value)) return 'ok';
  const [warn, crit] = THRESHOLDS[kind] || THRESHOLDS.default;
  if (value >= crit) return 'crit';
  if (value >= warn) return 'warn';
  return 'ok';
}

export function emojiFor(kind, value) { return LEVELS[severity(kind, value)].emoji; }
export function wordFor(kind, value) { return LEVELS[severity(kind, value)].word; }

/** bytes → "5.5 GB" — binary units, plain language over raw byte counts. */
export function fmtBytes(n) {
  if (n == null || Number.isNaN(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = Number(n), i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(i === 0 || v >= 10 ? 0 : 1)} ${units[i]}`;
}

/** seconds → "7d 3h" — coarsest two units only; nobody needs the minutes. */
export function fmtUptime(sec) {
  if (sec == null || Number.isNaN(sec)) return '—';
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function fmtPercent(n, digits = 0) {
  if (n == null || Number.isNaN(n)) return '—';
  return `${Number(n).toFixed(digits)}%`;
}

/**
 * "Memory 75% — 5.5 GB of 7.7 GB used" style plain-language sentence.
 * Prefer this over showing a bare field name + number.
 */
export function usageSentence(label, percent, used, total) {
  const pct = fmtPercent(percent);
  if (used == null || total == null) return `${label} ${pct}`;
  return `${label} ${pct} — ${fmtBytes(used)} of ${fmtBytes(total)} used`;
}

/**
 * A gauge card: emoji + plain label + big value + proportional bar.
 * `percent` (0-100) drives both the bar width and the severity colour/emoji;
 * pass `value`/`unit` when the displayed text isn't the percent itself
 * (e.g. a °C reading, still classified on the same 0-100 severity scale).
 */
export function gauge({ kind = 'default', label, percent, value, unit = '%', sub }) {
  const lvl = severity(kind, percent);
  const { emoji, badge } = LEVELS[lvl];
  const shown = value != null ? `${value}${unit}` : fmtPercent(percent);
  const pct = Math.max(0, Math.min(100, percent ?? 0));
  return el('div.card', { style: 'text-align:center' }, [
    el('div', { style: 'font-size:1.3rem;line-height:1', text: emoji }),
    el('div.data', { style: 'font-size:1.35rem;font-weight:700;margin:3px 0', text: shown }),
    el('div.kicker', { text: label }),
    el('div.gauge-bar', {}, [el(`div.gauge-fill.${badge}`, { style: `width:${pct}%` })]),
    sub ? el('div.muted', { style: 'font-size:.7rem;margin-top:4px', text: sub }) : null,
  ]);
}

/** Small severity badge for non-gauge contexts (list rows, headers). */
export function severityBadge(kind, value, text) {
  const { badge, emoji } = LEVELS[severity(kind, value)];
  return el(`span.badge.${badge}`, { text: `${emoji} ${text}` });
}
