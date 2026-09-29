// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
import { describe, expect, it } from 'vitest';
import { trieFlux, FLUX_MAX } from '../FluxHall';

const ev = (id: string, priorite: number, at: number) => ({ id, titre: id, priorite, at });

describe('trieFlux', () => {
  it('jamais plus de trois événements', () => {
    expect(trieFlux([ev('a', 0, 1), ev('b', 0, 2), ev('c', 0, 3), ev('d', 0, 4)])).toHaveLength(FLUX_MAX);
  });
  it('priorité d’abord, puis le plus récent', () => {
    expect(trieFlux([ev('vieux', 5, 1), ev('recent', 0, 9), ev('urgent', 9, 2), ev('neuf', 5, 8)]).map(x => x.id))
      .toEqual(['urgent', 'neuf', 'vieux']);
  });
});
