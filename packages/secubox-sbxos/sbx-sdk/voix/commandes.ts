// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/**
 * Commandes vocales COURANTES (#1656) : une grammaire fermée, reconnue dans le
 * navigateur, qui s'exécute sans attendre de transcription. Pur et testé.
 */
export type Commande =
  | { kind: 'espace'; id: string; dit: string }
  | { kind: 'media'; action: string; v?: unknown; dit: string }
  | { kind: 'ferme'; dit: string };

import liste from '../../../secubox-voice/conf/commandes.json';

const ESPACES: Record<string, string> = liste.espaces;
const MEDIA: Record<string, { action: string; v?: unknown }> = liste.media;
const FERME: string[] = liste.ferme;
const PREFIXES: string[] = liste.prefixes_espace;

/** Phrases données à Vosk (grammaire fermée) ; « [unk] » absorbe le reste. */
export const GRAMMAIRE: string[] = [
  ...Object.keys(MEDIA), ...FERME,
  ...Object.keys(ESPACES), ...PREFIXES.flatMap(p => Object.keys(ESPACES).map(e => `${p} ${e}`)),
  '[unk]',
];

const norme = (s: string) => s.toLowerCase().replace(/\[unk\]/g, ' ').replace(/[^\p{L}' ]/gu, ' ').replace(/\s+/g, ' ').trim();

/** Le texte reconnu est-il EXACTEMENT une commande ? Sinon null (→ transcription complète). */
export function comprend(texte: string | null | undefined): Commande | null {
  const t = norme(texte ?? '');
  if (!t) return null;
  if (t in MEDIA) return { kind: 'media', ...MEDIA[t], dit: t };
  if (FERME.includes(t)) return { kind: 'ferme', dit: t };
  const p = PREFIXES.find(x => t.startsWith(x + ' '));
  const e = p ? t.slice(p.length + 1) : t;
  if (e in ESPACES) return { kind: 'espace', id: ESPACES[e], dit: t };
  return null;
}
