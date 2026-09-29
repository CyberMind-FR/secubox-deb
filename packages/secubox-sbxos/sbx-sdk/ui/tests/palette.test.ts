// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
import { describe, expect, it } from 'vitest';
import { espaceDemande } from '../../../app/src/Palette';
import { sansClic } from '@sbx/data';

const E = [{ id: 'hall', nom: 'Hall' }, { id: 'atelier', nom: 'Atelier' }, { id: 'media', nom: 'Média' }, { id: 'securite', nom: 'Sécurité' }];

describe('palette', () => {
  it('navigation résolue sur place', () => {
    expect(espaceDemande('ouvre atelier', E)).toBe('atelier');
    expect(espaceDemande('va dans média', E)).toBe('media');
    expect(espaceDemande('Sécurité', E)).toBe('securite');
    expect(espaceDemande('mets la radio en pause', E)).toBeNull();
  });
  it('seules les actions média partent sans clic', () => {
    expect(sansClic({ kind: 'sbx-action', service: 'radio', action: 'media.pause' })).toBe(true);
    expect(sansClic({ kind: 'sbx-action', service: 'zigbee', action: 'lumiere.on' })).toBe(false);
  });
});
