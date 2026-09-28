// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * SDK Aurora :: <SbxIcon> (#1594). Raster seulement : les 120 masters 512 px
 * sont déclinés au build (outils/art.mjs) en /sbxos/art/icons/<id>-<taille>[-<état>].webp.
 */
import manifeste from './manifest.json';

export type Etat = 'repos' | 'alerte' | 'succes';
const TAILLES = [64, 128, 256] as const;
const CONNUS = new Set(manifeste.icones.map(i => i.id));
export const ICONES = manifeste.icones;

export function urlIcone(id: string, px: number, etat: Etat = 'repos'): string {
  const t = TAILLES.find(x => x >= px * (window.devicePixelRatio || 1)) ?? 256;
  return `/sbxos/art/icons/${id}-${t}${etat === 'repos' ? '' : '-' + etat}.webp`;
}

export function SbxIcon({ id, taille = 48, etat = 'repos', label }:
  { id: string; taille?: number; etat?: Etat; label?: string }) {
  if (!CONNUS.has(id)) return null;
  const nom = label ?? manifeste.icones.find(i => i.id === id)?.label ?? id;
  return <img src={urlIcone(id, taille, etat)} width={taille} height={taille} alt={nom}
              decoding="async" loading="lazy" draggable={false} />;
}
