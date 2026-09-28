// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SDK Aurora :: données. LE SEUL code qui parle à la box : même origine,
 * JSON exigé (un /api/ non relayé rend l'index du Hall en 200), texte seulement.
 */
export async function sbxFetch<T>(chemin: string, init: RequestInit = {}): Promise<T | null> {
  if (!chemin.startsWith('/') || chemin.startsWith('//')) return null;
  try {
    const r = await fetch(chemin, { credentials: 'same-origin', ...init,
                                    headers: { Accept: 'application/json', ...(init.headers || {}) } });
    if (!r.ok || !(r.headers.get('content-type') || '').includes('json')) return null;
    return (await r.json()) as T;
  } catch { return null; }
}

export type Entree = 'deja' | 'ouverte' | 'aucun';

/**
 * Entrée sans mot de passe (#1562), en UNE promesse : session déjà là, sinon
 * la clé de l'appareil (IndexedDB de cette origine) ouvre la session, sinon
 * rien — l'interface propose alors /acces/. Jamais de session par-dessus une autre.
 */
let entree: Promise<Entree> | null = null;
export function entrer(): Promise<Entree> {
  entree ??= (async () => {
    const e = await sbxFetch<{ session: boolean }>('/api/v1/acces/session/etat');
    if (e?.session) return 'deja';
    try {
      const url = '/acces/appareil.js';     // servi par le Hall, hors du bundle
      const acces: { ouvreSiAdmis(): Promise<boolean> } = await import(/* @vite-ignore */ url);
      return (await acces.ouvreSiAdmis()) ? 'ouverte' : 'aucun';
    } catch { return 'aucun'; }
  })();
  return entree;
}

export type Moi = { identite: { pseudo?: string; display_name?: string; user_uuid?: string } | null; sub?: string };
export const moi = () => sbxFetch<Moi>('/api/v1/sbxid/moi');
