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

// ── Manifeste de session (#1610) : ce que la box déclare pour CET appelant ──
export type Module = { id: string; label: string; url: string | null; lan: boolean; etat?: string };
export type EspaceM = { id: string; nom: string; guide: string; modules: Module[] };
export type Manifeste = {
  version: number; role: 'guest' | 'user' | 'admin'; lan: boolean; domaine: string;
  espaces: EspaceM[]; ecrans: Record<string, string>; capacites: Record<string, boolean>;
};

/** Garde de forme : une charge invalide est ignorée, jamais affichée à moitié. */
function estManifeste(x: unknown): x is Manifeste {
  const m = x as Manifeste;
  return !!m && m.version === 1 && Array.isArray(m.espaces)
    && m.espaces.every(e => typeof e.id === 'string' && Array.isArray(e.modules));
}

export async function manifeste(): Promise<Manifeste | null> {
  const m = await sbxFetch<unknown>('/api/v1/webos/sbxos/manifeste');
  return estManifeste(m) ? m : null;
}

/** Une URL sortie du manifeste n'est suivie que si elle vise le domaine de la box. */
export function urlSure(url: string | null, domaine: string): string | null {
  if (!url) return null;
  try {
    const u = new URL(url, location.origin);
    if (u.protocol !== 'https:' || !domaine) return null;
    return u.hostname === domaine || u.hostname.endsWith('.' + domaine) ? u.href : null;
  } catch { return null; }
}

export type Radio = { piste?: { titre?: string; auteur?: string } | null };
export const radioCourante = () => sbxFetch<Radio>('/api/v1/radio/current');

// ── Fil d'activité (#1560) : déjà filtré par la box selon la personne ──────
export type Activite = { activity_uuid: string; kind: string; qui?: string; at: number;
                         context?: { titre?: string; lien?: string; salon_titre?: string } };
export async function activites(n = 6): Promise<Activite[]> {
  const r = await sbxFetch<{ activites?: Activite[] }>(`/api/v1/sbxid/activite?n=${n}`);
  return Array.isArray(r?.activites) ? r!.activites.filter(a => typeof a.activity_uuid === 'string') : [];
}

/** Un lien d'activité n'est suivi que s'il reste sur cette origine. */
export const lienLocal = (l?: string) => (l && l.startsWith('/') && !l.startsWith('//') ? l : null);

// ── ZIA (#1615) : le SEUL cerveau. La palette présente, ZIA décide. ────────
export type ObjetZia = { id: string; type: string; service?: string; title?: string; summary?: string; url?: string };
export type ActionZia = { kind: 'sbx-action'; service: string; action: string; params?: Record<string, unknown>;
                         effet?: 'media' | 'lecture' | 'physique' | 'ecriture' };
export type ReponseZia = { text: string; objects: ObjetZia[]; actions: ActionZia[] };

export async function demandeZia(message: string): Promise<ReponseZia | null> {
  const m = message.trim().slice(0, 500);
  if (!m) return null;
  const r = await sbxFetch<ReponseZia>('/api/v1/zia/v1/chat', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ message: m }) });
  if (!r || typeof r.text !== 'string') return null;
  return { text: r.text, objects: Array.isArray(r.objects) ? r.objects : [],
           actions: Array.isArray(r.actions) ? r.actions.filter(a => a?.kind === 'sbx-action') : [] };
}

/** Seules les actions dont la capacité DÉCLARE effet=media s'exécutent sans clic (#1615) ;
 *  une action sans classe est une écriture : elle demande confirmation. */
export const sansClic = (a: ActionZia) => a.effet === 'media';
