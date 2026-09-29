// SPDX-License-Identifier: LicenseRef-CMSD-1.0
// Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
// Source-Disclosed License — All rights reserved except as expressly granted.
// See LICENCE-CMSD-1.0.md for terms.
import { describe, expect, it } from 'vitest';
import { comprend, GRAMMAIRE } from '../commandes';

describe('commandes vocales', () => {
  it('média', () => {
    expect(comprend('mets la radio en pause')).toMatchObject({ kind: 'media', action: 'media.pause' });
    expect(comprend('Coupe le son')).toMatchObject({ kind: 'media', action: 'media.mute', v: true });
  });
  it('Espaces', () => {
    expect(comprend('ouvre atelier')).toMatchObject({ kind: 'espace', id: 'atelier' });
    expect(comprend('va dans sécurité')).toMatchObject({ kind: 'espace', id: 'securite' });
    expect(comprend('média')).toMatchObject({ kind: 'espace', id: 'media' });
  });
  it('hors grammaire → transcription complète', () => {
    expect(comprend('[unk]')).toBeNull();
    expect(comprend('cherche les sujets récents')).toBeNull();
    expect(comprend('pause [unk] atelier')).toBeNull();
  });
  it('la grammaire se termine par [unk]', () => { expect(GRAMMAIRE.at(-1)).toBe('[unk]'); });
});
