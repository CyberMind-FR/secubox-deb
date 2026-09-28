// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SDK Aurora :: protocole sbx, côté ENFANT (Aurora encadrée dans le Hall,
 * HIG.md §4.1–4.2). N'écoute que le cadre parent de MÊME origine ; ne répond
 * qu'à cette origine, jamais à '*'.
 */
export type Poignees = { relis?: () => void };

export function estEncadre(): boolean {
  try { return window.top !== window; } catch { return true; }
}

function envoie(msg: Record<string, unknown>) {
  if (estEncadre()) window.parent.postMessage(msg, location.origin);
}

/** Zones d'aide : les éléments marqués data-aide="libellé", en px de la vue. */
function zones() {
  return [...document.querySelectorAll<HTMLElement>('[data-aide]')].map((el) => {
    const r = el.getBoundingClientRect();
    return { label: el.dataset.aide ?? '', x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
  });
}

export function ecoute(p: Poignees = {}): () => void {
  const q = new URLSearchParams(location.search).get('theme');
  if (q === 'dark' || q === 'light') document.documentElement.dataset.theme = q;
  const f = (ev: MessageEvent) => {
    if (ev.source !== window.parent || ev.origin !== location.origin) return;
    const d = ev.data as { sbx?: string; theme?: string } | null;
    if (!d || typeof d.sbx !== 'string') return;
    if (d.sbx === 'theme' && (d.theme === 'dark' || d.theme === 'light')) document.documentElement.dataset.theme = d.theme;
    else if (d.sbx === 'relis') p.relis?.();
    else if (d.sbx === 'aide?') envoie({ sbx: 'aide-zones', slice: 0, vw: innerWidth, vh: innerHeight, zones: zones() });
  };
  addEventListener('message', f);
  return () => removeEventListener('message', f);
}

/** Ouvrir un module : encadrée en mega, on le demande au Hall au lieu d'imbriquer. */
export function demandeOuverture(id: string): boolean {
  if (!estEncadre()) return false;
  envoie({ sbx: 'ouvre', id });
  return true;
}
