// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
/** SDK Aurora :: jetons. Les valeurs vivent dans tokens.css ; ici, leurs noms. */
import './tokens.css';

export type Rendu = 'complet' | 'leger';

/** Profil de rendu : ?rendu=leger, mouvement réduit ou économie de données → Léger. */
export function renduInitial(): Rendu {
  const q = new URLSearchParams(location.search).get('rendu');
  if (q === 'leger' || q === 'complet') return q;
  const nav = navigator as Navigator & { connection?: { saveData?: boolean } };
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || nav.connection?.saveData) return 'leger';
  return 'complet';
}
